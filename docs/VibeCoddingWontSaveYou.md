# Vibe Coding Won't Save You - But It Might Make You a Better Architect and PM

Vibe Coding is suddenly everywhere. The ability to turn idea into app is astoundingly accelerated using the latest crop of AI coding tools, and the edge of what is possible is moving quickly. It is possible to use these tools build simle and completely functional applications in a matter of minutes. But larger or more complex applications are still a challenge. Using these tools to build a large application or to work in a team of developers presents some major challenges. I spent the hackathon week setting out to build an ambitious application using these tools, and the most important thing I learned is that good PM and eng architecture skills are still the most important part of building a successful application. Let's explore that conclusion and the lessons I learned along the way.

## The Project

I set out to build a ["Vulnerability Assessment Copilot"](https://github.com/rysweet/skwaq/blob/rysweet-impl/Specifications/VulnerabilityAssessmentCopilot.md) "*an AI-driven multiagent system designed to assist vulnerability researchers in analyzing software codebases to identify potential vulnerabilities. It leverages structured ingestion, semantic indexing, and interactive workflows to facilitate comprehensive vulnerability assessments.*"

The goal was to build a system that could ingest a codebase, analyze it, and then provide a report on potential vulnerabilities. The system would be able to interact with the user, ask questions, and provide suggestions. The project was ambitious, but I thought it would be a good test of the capabilities of the latest AI coding tools.

## The Process

**1st pass, good but not great**: I started by articulating what I wanted in a couple of pages of text (linked above). Then I used the AI to turn that into massive (6000 lines) Implementation Plan. Then I worked iwth the AI to refine the implementation plan and break it into milestones. Once we had a set of milestones that seemed to make sense, I turned the AI loose to build it. At first the AI worked through each milestone and built tests for the milestone and made great progress. But after time I noticed cracks in the veneer. There were lots of places where the implementation went off the rails or was not following the guidelines I had set out. The AI was not able to keep track of the overall architecture and the implementation was not consistent with the architecture. I also noticed that the AI was playing fast and loose with the idea of a "test". More on that later.

**2nd pass, better but still not great**: I tried to think about what it was doing well and where it was making mistakes. *I realized I was being a terrible PM and the results were the same bad results I would get if I took this approach with a team of humans, only faster.* I was not clearly specifying the software and its acceptance criteria I was articulating a vision, but not a good specification. I was not breaking the work down into smaller pieces that could be built and tested independently. I was not validating the implementation as it was being built. I was not keeping track of the overall architecture and how the pieces fit together. I was not thinking about how to manage the complexity of the project. So for the the second pass, I went back to the tried and true skills of a good PM and architect. I took the time to write detailed user stories and acceptance criteria. I focused on much smaller pieces of the whole thing. Since my project was complex, I picked a smaller part, earlier in the usage scenario - the ingestion pieces. I threw out the terrible code the AI had written on its own, and [started over](https://github.com/rysweet/skwaq/blob/rysweet-impl/Specifications/Ingestion.md). The resulting spec for the feature set is stil only a few pages but now it is a clear and concise description of what needed to be built with clear acceptance criteria. That resulted in much [more interesting/usable code](https://github.com/rysweet/skwaq/tree/rysweet-impl/skwaq/ingestion). I still had to use probably two dozen more iterations of prompt, review, test, etc to get to a working implementation, but it was more guiding things to my preferences and discouraging the sillier ideas the LLM agents were coming up with. 

With this refactoring I was able to see a path to go from the wild and wooly mess that was initially generated to a more structured and coherent implementation.  It is certainly not done yet, but the way forward is clear. What follows are some lessons learned from the process.

## Explore your idea and refine it narratively

### Figure out any big open questions (eg about workflow, UI, data models)

At this point - if you have big open questions about what you should be building, you can use rapid prototyping to explore the idea and refine it. This is different from setting out to build an application. This is more like a design sprint. You want to narow the the scope to just help you answer the open questions. It is really unlikely that you want to keep code and context from this phase. Build your prototype, focus on key features, and then park it somewhere. Extract from it the details you need to have a clear specification.

### Write detailed user stories and acceptance criteria 

This takes time but is worth it. This is just a best practice of good software development. You need to know what you are building and how you will know when it is done.

### Define the architecture

Identify the components of the system and how they will interact. This is a good time to think about the data models, the workflows, and the user interface. You can have a conversation with the AI to discuss aspects of the architecture. You have to be careful though because it wants to please you and will often give you what you want to hear. It is important to be critical of the suggestions it makes and to ask follow up questions. You can also use the AI to generate diagrams and other artifacts that will help you visualize the architecture.

### Define the tech stack

If you are unsure about what tech you should be using, you can use the AI tools to help you explore the options. You can ask it to generate code in different languages and frameworks, and then compare the results. This is a great way to get a feel for what is possible and what will work best for your project. While you are doing this, collect the best resources that illustrate how to use the stack you hae chosen, you will need them later.

## Turn your artifacts into a plan

For each component of the system, you need to define an implementation plan. you can work with the model to do this, but don't accept its plans wholesale. You need to review the plans and make sure they make sense and match your vision for the system. You can also use the AI to help you identify potential issues and risks, and to come up with mitigation strategies.

## Identify milestones that build on each other

Try to phase the project into smaller pieces that build on each other. This will help you to manage the complexity of the project and to keep the momentum going. You can use the AI to help you identify potential milestones and to come up with a plan for how to achieve them. Try to indentify if there are pieces that do not depend on one another and can go in parallel. 

## Make the high level plan a LOT more detailed

Once you have top level plan, you need to break it down into smaller pieces. This is where the AI can really help you. You can use it to generate code snippets, and then use those snippets to build out the components of the system. You can also use it to generate tests plans and other artifacts that will help you validate the implementation. You need to think of this as the plan that a scrum leader would use to break down the work for a team of developers. You need to be able to hand this plan off to someone else and have them be able to execute it.  Here are some sections you might have in each module's specification:

* **Overview**: A brief description of the module and its purpose.
* **Dependencies**: A list of any dependencies that the module has, including other modules, libraries, and frameworks.
* **Data Models**: A description of the data models that the module will use, including any relationships between them.
* **Workflows**: A description of the workflows that the module will support, including any user interactions and data flows.
* **User Interface**: A description of the user interface that the module will use, including any screens, forms, and controls.
* **Acceptance Criteria**: A list of acceptance criteria that the module must meet, including any performance, security, and usability requirements.
* **Tests**: A description of the tests that will be used to validate the implementation, including any unit tests, integration tests, and end-to-end tests.
* **Implementation Plan**: A detailed plan for how the module will be implemented, including any code snippets, algorithms, and data structures that will be used.
* **Risks and Mitigation**: A list of potential risks and issues that may arise during the implementation, along with strategies for mitigating them.

## Build the system in small pieces

Turn the AI loose on your individual pieces and the acceptance criteria for each piece. Make it run all the tests. MAke sure the tests actually validate the implementation. 

## Use the AI to checkpoint progress as you go. 

I told it to keep track of the progress and summarize the decisions made, the problems encountered, and the next steps in a status.md file. This was a great way to keep track of the progress and to make sure that the implementation was on track. This really helped when sessions crashed or I switched between technologies etc. 

## Use the time while the agents are working to work on the next prompts

I kept a backlog of prompts that I wanted to run next. I would work on the next prompt while the agents were working on the current prompt. This helped me to keep the momentum going and to make sure that I was always moving forward and thinking about how to structure the next piece of work.  I also kept a list of prompts that I used repeatedly to validate progress, put things back on track, etc. 

## Keep a file with commonly used prompts on hand

I started keeping prompts that I would use to encourage the agents to do things like keep running the tests and fixing errors until they all passed, etc. I also kept a list of prompts that I would use to get the agents to generate code snippets, tests, and other artifacts. This was a great way to keep track of the prompts that worked well and to make sure that I was using them consistently.

## Stop and refactor along the way

Pay attention to what the AI is doing and when you spot problems - eg classes or methods that are too long or have too many concerns - stop and refactor. Record these decisions in the status.md file. This will help you to keep the implementation clean and to make sure that it is easier to maintain. It will also prevent the AI from getting too far off track as it continues with the implementation.

## The model is lazy AF

- it will fall back on mocks and stubs for the sake of saying something works but goes out of its way to make it look magical
- it will gloss over failing tests and sweep them under the rug
- it will make you think you are done when you are not

## Overfitting

Its easy for the model to overfit for the code you have vs the code you want - this is a problem if the code you have was largely written by the model or was a fast prototype. Don't be afraid to throw out code it wrote and start over. 

The other way the model can overfit is by giving too much weight to something you tell it, blindly pursuing the current goal at the expense of the overall project. Don't be afraid to tell it how to prioritize. 

## Log your prompts and results

Ask the agents to keep a log of the prompts you use and the results you get. This will help you to identify patterns and to come up with better prompts in the future.