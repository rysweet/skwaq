"""Intent inference for code analysis.

This module provides functionality for inferring developer intent
from code at different levels of abstraction.
"""

import re
import ast
from typing import Dict, Any, List, Optional, Set

from ...utils.logging import get_logger, LogEvent
from ...utils.config import get_config
from ...core.openai_client import get_openai_client

logger = get_logger(__name__)


class IntentInferenceEngine:
    """Infers developer intent from code.
    
    This class provides functionality for inferring the intent behind
    code at function, class, and module levels.
    """
    
    def __init__(self) -> None:
        """Initialize the intent inference engine."""
        self.config = get_config()
        self.openai_client = get_openai_client(async_mode=True)
        
        # Load intent inference prompts from config
        self.intent_prompts = {
            "function": self.config.get(
                "intent_inference.prompts.function",
                "Analyze this function and identify its intent or purpose. "
                "Why was this function created? What problem is it solving? "
                "Return your answer in JSON format with fields 'intent' (one-line summary), "
                "'purpose' (detailed explanation), and 'confidence' (0.0-1.0 float).\n\nCode:\n{code}"
            ),
            "class": self.config.get(
                "intent_inference.prompts.class",
                "Analyze this class and identify its intent or purpose. "
                "Why was this class created? What domain concept does it represent? "
                "Return your answer in JSON format with fields 'intent' (one-line summary), "
                "'purpose' (detailed explanation), and 'confidence' (0.0-1.0 float).\n\nCode:\n{code}"
            ),
            "module": self.config.get(
                "intent_inference.prompts.module",
                "Analyze this module and identify its intent or purpose. "
                "Why was this module created? What functionality does it provide? "
                "Return your answer in JSON format with fields 'intent' (one-line summary), "
                "'purpose' (detailed explanation), and 'confidence' (0.0-1.0 float).\n\nCode:\n{code}"
            )
        }
        
        # Set default model
        self.default_model = self.config.get("intent_inference.default_model", "o1")
        
        logger.info("IntentInferenceEngine initialized with LLM capabilities")
    
    async def _get_llm_intent(self, code: str, level: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Get intent inference from LLM for the provided code.
        
        Args:
            code: Code to analyze
            level: Level of intent inference (function, class, module)
            context: Optional additional context
            
        Returns:
            Dictionary with intent information
        """
        if not context:
            context = {}
            
        model = context.get("model", self.default_model)
        language = context.get("language", "python")
        
        # Get the appropriate prompt template
        prompt_template = self.intent_prompts.get(level, self.intent_prompts["function"])
        
        # Format the prompt
        prompt = prompt_template.format(code=code)
        
        # Add language information to the prompt
        prompt = f"Programming language: {language}\n\n{prompt}"
        
        try:
            # Get completion from OpenAI
            response = await self.openai_client.create_completion(
                prompt=prompt,
                model=model,
                temperature=0.1,  # Lower temperature for more factual analysis
                max_tokens=500,
                response_format={"type": "json"}
            )
            
            # Extract the response text
            response_text = response.get("choices", [{}])[0].get("text", "").strip()
            
            # Parse the JSON response
            import json
            try:
                intent_data = json.loads(response_text)
                
                # Ensure required fields exist
                if "intent" not in intent_data:
                    intent_data["intent"] = f"Unknown {level} intent"
                if "purpose" not in intent_data:
                    intent_data["purpose"] = "Purpose could not be determined"
                if "confidence" not in intent_data:
                    intent_data["confidence"] = 0.5
                elif not isinstance(intent_data["confidence"], (int, float)):
                    intent_data["confidence"] = float(intent_data["confidence"])
                    
                return intent_data
            except json.JSONDecodeError:
                # If JSON parsing fails, extract information using regex
                logger.warning(f"Failed to parse JSON response from LLM: {response_text}")
                return self._extract_intent_with_regex(response_text, level)
                
        except Exception as e:
            logger.error(f"Error getting LLM intent inference: {e}")
            return {
                "intent": f"Error analyzing {level}",
                "purpose": f"Error during analysis: {str(e)}",
                "confidence": 0.0
            }
    
    def _extract_intent_with_regex(self, text: str, level: str) -> Dict[str, Any]:
        """Extract intent information from text using regex when JSON parsing fails.
        
        Args:
            text: Raw LLM response text
            level: Level of intent inference
            
        Returns:
            Dictionary with intent information
        """
        intent_data = {
            "intent": f"Unknown {level} intent",
            "purpose": "Purpose could not be determined",
            "confidence": 0.5
        }
        
        # Try to extract intent
        intent_match = re.search(r"intent[:\s]+(.*?)(?:$|\n|\.)", text, re.IGNORECASE)
        if intent_match:
            intent_data["intent"] = intent_match.group(1).strip()
            
        # Try to extract purpose
        purpose_match = re.search(r"purpose[:\s]+(.*?)(?:$|\n\n|\n[A-Z])", text, re.IGNORECASE | re.DOTALL)
        if purpose_match:
            intent_data["purpose"] = purpose_match.group(1).strip()
            
        # Try to extract confidence
        confidence_match = re.search(r"confidence[:\s]+([0-9.]+)", text, re.IGNORECASE)
        if confidence_match:
            try:
                intent_data["confidence"] = float(confidence_match.group(1))
            except ValueError:
                pass
                
        return intent_data
    
    def _extract_function_info_for_intent(self, function_code: str) -> Dict[str, Any]:
        """Extract information from function code to assist with intent inference.
        
        Args:
            function_code: Function code to analyze
            
        Returns:
            Dictionary with function information for intent analysis
        """
        info = {
            "name": "unknown_function",
            "docstring": None,
            "params": [],
            "param_types": [],
            "return_type": None,
            "raises": [],
            "calls": [],
            "conditionals": []
        }
        
        try:
            # Parse the code with ast
            tree = ast.parse(function_code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Extract function name
                    info["name"] = node.name
                    
                    # Extract docstring
                    if (ast.get_docstring(node)):
                        info["docstring"] = ast.get_docstring(node)
                    
                    # Extract parameters
                    for arg in node.args.args:
                        info["params"].append(arg.arg)
                        if arg.annotation:
                            info["param_types"].append(ast.unparse(arg.annotation))
                    
                    # Extract return type
                    if node.returns:
                        info["return_type"] = ast.unparse(node.returns)
                        
                    # Extract function calls
                    for subnode in ast.walk(node):
                        # Function calls
                        if isinstance(subnode, ast.Call):
                            if isinstance(subnode.func, ast.Name):
                                info["calls"].append(subnode.func.id)
                            elif isinstance(subnode.func, ast.Attribute):
                                info["calls"].append(subnode.func.attr)
                                
                        # Conditional statements (for control flow analysis)
                        elif isinstance(subnode, ast.If):
                            if isinstance(subnode.test, ast.Compare):
                                left = ast.unparse(subnode.test.left) if hasattr(subnode.test, "left") else ""
                                info["conditionals"].append(left)
                    
                    break  # Only analyze the first function
        except Exception as e:
            logger.error(f"Error extracting function info for intent: {e}")
            
        return info
    
    @LogEvent("infer_function_intent")
    async def infer_function_intent(self, function_code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Infer intent for a function.
        
        Args:
            function_code: Function code to analyze
            context: Optional additional context
            
        Returns:
            Dictionary with inferred intent information
        """
        if not context:
            context = {}
            
        # Extract basic function information
        func_info = self._extract_function_info_for_intent(function_code)
        
        # Enhance context with function info
        enhanced_context = {**context}
        if func_info["docstring"]:
            enhanced_context["docstring"] = func_info["docstring"]
            
        # Get intent from LLM
        intent_data = await self._get_llm_intent(function_code, "function", enhanced_context)
        
        # If we have a good docstring and low LLM confidence, use docstring for intent
        if func_info["docstring"] and intent_data.get("confidence", 0) < 0.7:
            docstring = func_info["docstring"]
            first_line = docstring.split('\n')[0].strip()
            
            if first_line:
                intent_data["intent"] = first_line
                if len(docstring.split('\n')) > 1:
                    intent_data["purpose"] = '\n'.join(docstring.split('\n')[1:]).strip()
                intent_data["confidence"] = 0.8  # Higher confidence for direct docstring
                intent_data["source"] = "docstring"
                
        # If the function name is very descriptive, use it to enhance intent
        if len(func_info["name"]) > 8 and '_' in func_info["name"] and intent_data.get("confidence", 0) < 0.8:
            name_parts = func_info["name"].split('_')
            verb = name_parts[0]
            object_parts = name_parts[1:]
            
            if verb in ["get", "fetch", "retrieve", "load", "read"]:
                intent_data["intent"] = f"Retrieves {' '.join(object_parts)}"
                intent_data["confidence"] = max(intent_data.get("confidence", 0), 0.7)
            elif verb in ["set", "update", "modify", "change"]:
                intent_data["intent"] = f"Updates {' '.join(object_parts)}"
                intent_data["confidence"] = max(intent_data.get("confidence", 0), 0.7)
            elif verb in ["create", "make", "generate", "build"]:
                intent_data["intent"] = f"Creates {' '.join(object_parts)}"
                intent_data["confidence"] = max(intent_data.get("confidence", 0), 0.7)
            elif verb in ["delete", "remove", "destroy", "clean"]:
                intent_data["intent"] = f"Removes {' '.join(object_parts)}"
                intent_data["confidence"] = max(intent_data.get("confidence", 0), 0.7)
            elif verb in ["validate", "verify", "check", "ensure"]:
                intent_data["intent"] = f"Validates {' '.join(object_parts)}"
                intent_data["confidence"] = max(intent_data.get("confidence", 0), 0.7)
                
        return intent_data
    
    @LogEvent("infer_class_intent")
    async def infer_class_intent(self, class_code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Infer intent for a class.
        
        Args:
            class_code: Class code to analyze
            context: Optional additional context
            
        Returns:
            Dictionary with inferred intent information
        """
        if not context:
            context = {}
            
        # Extract class docstring for context enhancement
        docstring = None
        try:
            tree = ast.parse(class_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    docstring = ast.get_docstring(node)
                    break
        except Exception:
            pass
            
        # Enhance context with docstring
        enhanced_context = {**context}
        if docstring:
            enhanced_context["docstring"] = docstring
            
        # Get intent from LLM
        intent_data = await self._get_llm_intent(class_code, "class", enhanced_context)
        
        # If we have a good docstring and low LLM confidence, use docstring for intent
        if docstring and intent_data.get("confidence", 0) < 0.7:
            first_line = docstring.split('\n')[0].strip()
            
            if first_line:
                intent_data["intent"] = first_line
                if len(docstring.split('\n')) > 1:
                    intent_data["purpose"] = '\n'.join(docstring.split('\n')[1:]).strip()
                intent_data["confidence"] = 0.8  # Higher confidence for direct docstring
                intent_data["source"] = "docstring"
                
        return intent_data
    
    @LogEvent("infer_module_intent")
    async def infer_module_intent(self, module_code: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Infer intent for a module.
        
        Args:
            module_code: Module code to analyze
            context: Optional additional context
            
        Returns:
            Dictionary with inferred intent information
        """
        if not context:
            context = {}
            
        # Extract module docstring for context enhancement
        docstring = None
        try:
            tree = ast.parse(module_code)
            docstring = ast.get_docstring(tree)
        except Exception:
            pass
            
        # Enhance context with docstring
        enhanced_context = {**context}
        if docstring:
            enhanced_context["docstring"] = docstring
            
        # Get intent from LLM
        intent_data = await self._get_llm_intent(module_code, "module", enhanced_context)
        
        # If we have a good docstring and low LLM confidence, use docstring for intent
        if docstring and intent_data.get("confidence", 0) < 0.7:
            first_line = docstring.split('\n')[0].strip()
            
            if first_line:
                intent_data["intent"] = first_line
                if len(docstring.split('\n')) > 1:
                    intent_data["purpose"] = '\n'.join(docstring.split('\n')[1:]).strip()
                intent_data["confidence"] = 0.8  # Higher confidence for direct docstring
                intent_data["source"] = "docstring"
                
        return intent_data