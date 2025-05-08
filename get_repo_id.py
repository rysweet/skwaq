from neo4j import GraphDatabase

def get_repo_ids():
    conn = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'password'))
    with conn.session() as session:
        result = session.run('MATCH (r:Repository) RETURN id(r) as id, r.name as name, r.ingestion_id as ingestion_id')
        return [(record['id'], record['name'], record['ingestion_id']) for record in result]

if __name__ == "__main__":
    repos = get_repo_ids()
    for repo_id, name, ingestion_id in repos:
        print(f"ID: {repo_id}, Name: {name}, Ingestion ID: {ingestion_id}")
