# Prebuilt artifacts

Following [our build instructions](build.md) step-by-step can be a very
time-consuming task. To speed up the process, prebuilt artifacts are available.

- Instead of running `docker-compose build`, you can pull container
  [`ipasim/build`](https://hub.docker.com/r/ipasim/build):

  ```bash
  docker pull ipasim/build
  ```

- Instead of running `./scripts/build.ps1`, you can pull container
  [`ipasim/artifacts`](https://hub.docker.com/r/ipasim/artifacts) and then start
  the container like this:

  ```bash
  docker pull ipasim/artifacts
  docker tag ipasim/artifacts ipasim/build
  docker-compose run --name ipasim ipasim powershell
  ```
