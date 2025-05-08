#!/usr/bin/env python3
from neo4j import GraphDatabase

def check_database():
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'skwaqdev'))
    with driver.session() as session:
        # Check AST nodes with code property
        result = session.run('MATCH (n:Function) WHERE n.code IS NOT NULL RETURN count(n) as count')
        record = result.single()
        print(f'AST nodes with code property: {record["count"]}')
        
        # Check AST nodes without code property
        result = session.run('MATCH (n:Function) WHERE n.code IS NULL RETURN count(n) as count')
        record = result.single()
        print(f'AST nodes without code property: {record["count"]}')
        
        # Check relationships between AST nodes and files
        result = session.run('MATCH (n:Function)-[:PART_OF]->(f:File) RETURN count(n) as count')
        record = result.single()
        print(f'Function nodes with PART_OF relationship to File: {record["count"]}')
        
        # Check AI summaries
        result = session.run('MATCH (s:CodeSummary) RETURN count(s) as count')
        record = result.single()
        print(f'CodeSummary nodes: {record["count"]}')
        
        # Check relationships between AI summaries and AST nodes
        result = session.run('MATCH (s:CodeSummary)-[r]->(n:Function) RETURN type(r) as rel_type, count(r) as count')
        for record in result:
            print(f'CodeSummary to Function relationships ({record["rel_type"]}): {record["count"]}')
    
    driver.close()

if __name__ == "__main__":
    check_database()