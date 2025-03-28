from skwaq.cli.commands.repository_commands import RepositoryCommandHandler
from skwaq.cli.commands.workflow_commands import InvestigationCommandHandler, SourcesAndSinksCommandHandler
import asyncio
import os

class MockArgs:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

async def ingest_repository():
    # Create mock args for repository ingest command
    args = MockArgs(
        url='https://github.com/dotnet/ai-samples',
        name='DotNet AI Samples',
        branch='main',
        depth=1
    )
    
    # Run repository ingest command
    print('Ingesting repository: https://github.com/dotnet/ai-samples')
    args.repo_command = 'add'
    handler = RepositoryCommandHandler(args)
    result = await handler.handle()
    
    if result != 0:
        print('Repository ingestion failed')
        return None
    
    # Get repository ID
    repo_id = handler.repo_id
    print(f'Repository ingested with ID: {repo_id}')
    
    return repo_id

async def create_investigation(repo_id):
    # Create mock args for investigation create command
    args = MockArgs(
        title='AI Samples Analysis',
        repo=repo_id,
        description='Analysis of dotnet/ai-samples repository',
        investigation_command='create'
    )
    
    # Run investigation create command
    print('Creating investigation')
    handler = InvestigationCommandHandler(args)
    result = await handler.handle()
    
    if result != 0:
        print('Investigation creation failed')
        return None
    
    # Use the returned investigation ID or a default one
    investigation_id = getattr(handler, 'investigation_id', None)
    if not investigation_id:
        print('Could not get investigation ID, using default')
        investigation_id = 'ai-samples-inv'
    print(f'Investigation created with ID: {investigation_id}')
    
    return investigation_id

async def run_sources_and_sinks(investigation_id):
    # Create mock args for sources and sinks command
    args = MockArgs(
        investigation=investigation_id,
        format='json',
        output=None
    )
    
    # Run sources and sinks command
    print('Running sources and sinks analysis')
    handler = SourcesAndSinksCommandHandler(args)
    result = await handler.handle()
    
    if result != 0:
        print('Sources and sinks analysis failed')
        return False
    
    print('Sources and sinks analysis completed')
    return True

async def run_visualization(investigation_id):
    # Create mock args for investigation visualize command
    args = MockArgs(
        id=investigation_id,
        format='html',
        output=os.path.join(os.getcwd(), 'docs/demos/ai-samples-visualization.html'),
        include_findings=True,
        include_vulnerabilities=True,
        include_files=True,
        investigation_command='visualize',
        max_nodes=500
    )
    
    # Run investigation visualize command
    print('Generating visualization')
    handler = InvestigationCommandHandler(args)
    result = await handler.handle()
    
    if result != 0:
        print('Visualization generation failed')
        return False
    
    print('Visualization generated')
    return True

async def main():
    try:
        # Ingest repository
        repo_id = await ingest_repository()
        if not repo_id:
            return
        
        # Create investigation
        investigation_id = await create_investigation(repo_id)
        if not investigation_id:
            return
        
        # Run sources and sinks analysis
        success = await run_sources_and_sinks(investigation_id)
        if not success:
            return
        
        # Generate visualization
        success = await run_visualization(investigation_id)
        if not success:
            return
        
        print('Process completed successfully')
        print(f'Visualization saved to: docs/demos/ai-samples-visualization.html')
    except Exception as e:
        print(f'Error: {str(e)}')

if __name__ == "__main__":
    asyncio.run(main())