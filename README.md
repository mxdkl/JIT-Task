# Dependency graph viewer for vulnerable npm packages 

## Running

1. Build the image:

    `docker build -t tool .`

2. Navigate to the directory containing the target repository.

3. Run the container with the target repository mounted:

    `docker run -v $(pwd)/<target-repo>:/repo tool`

## Testing

1. Create a virtual python environment in npm-vuln-graph/


2. Activate the environment and `pip install -r requirements.txt`

3. From npm-vuln-graph/, run `./<venv>/bin/pytest`
