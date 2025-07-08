# Security Researcher - SCA Task

By Max Dekel

## Running

1. Build the image:
bash ```docker build -t sca-task .```

2. Navigate to the directory containing the target repository:

3. Run the container with the target repository mounted:
bash ```docker run -v $(pwd)/<target-repo>:/repo sca-task```
