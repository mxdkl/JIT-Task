# Security Researcher - SCA Task

By Max Dekel

## Running

1. Build the image:

    `docker build -t sca-task .`

2. Navigate to the directory containing the target repository.

3. Run the container with the target repository mounted:

    `docker run -v $(pwd)/<target-repo>:/repo sca-task`

## Bonus

A -> B -> Z (vulnerable)

How would you discover which version of A removes the vulnerable version of
Z?

1. I would use `npm view A versions` to view all published versions of A in order.

2. For each version, use `npm view A@<version> dependencies --json` to see its dependencies.

3. Repeat recursively for all of As dependencies until a patched version of Z is pulled

4. This should get a patched version of Z while being the smallest possible upgrade of A
