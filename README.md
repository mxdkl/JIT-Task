# Dependency graph viewer for vulnerable npm packages 

## Running

1. Build the image:

    `docker build -t sca-task .`

2. Navigate to the directory containing the target repository.

3. Run the container with the target repository mounted:

    `docker run -v $(pwd)/<target-repo>:/repo sca-task`

## Testing

1. Create a virtual python environment in JIT-Task

2. Activate the environment and `pip install -r requirements.txt`

3. From JIT-Task/, run `./<venv>/bin/pytest`
