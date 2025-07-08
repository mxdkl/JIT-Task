# Security Researcher - SCA Task

By Max Dekel

## Running

1. Build the image:

```docker build -t sca-task .```

2. Navigate to the directory containing the target repository:

3. Run the container with the target repository mounted:

```docker run -v $(pwd)/<target-repo>:/repo sca-task```
