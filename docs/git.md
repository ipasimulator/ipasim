# Git

## Commit messages

Since our project's code base has grown rather large, we add tags in front of commit messages to categorize them.
See below for list of tags used and their respective meanings.
Also, we write commit messages as whole sentences (i.e., starting with capital letter and ending with a period).
And usually when there is more than one sentence, only the first is on the first line (along with the tag), acting as kind of a headline (some Git tools even highlight the first line).

### Tags

- [objc] - Objective-C runtime library (`/src/objc/`).
- [docs] - Documentation (`/docs/`).
- [deps] - 3rd-party dependencies (`/deps/`).
- [pthread] - `pthreads-win32` port (`/src/pthread/` and `/deps/pthreads.2/`).
- [res] - Resources (`/res/`).
- [uwp] - The main UWP application.
- [cg] - Code generation utilities (currently, that's the application called `HeadersAnalyzer` for historical reasons).
- [llvm] - LLVM and Clang port (`/deps/llvm/` and `/deps/clang/`).
- [woc] - WinObjC port (`/deps/WinObjC/`).
- [sam] - Samples (`/samples/`).
- [rtoc] - `RTObjCInterop` (`/src/RTObjCInterop/`).
- [build] - General build files (e.g., Docker and CMake files).

## Forking repositories

See [Microsoft docs](https://docs.microsoft.com/en-us/vsts/git/import-git-repository?view=vsts#manually-import-a-repo) for useful instructions.
Note that in the docs they use `git clone --bare`, but it seems better to use `git clone --mirror` (see also [this StackOverflow answer](https://stackoverflow.com/a/3960063/9080566)).
Basically, you should execute the following commands:

```cmd
git clone --mirror https://github.com/contoso/old-contoso-repo.git
cd old-contoso-repo.git
git push --mirror https://contoso-ltd.visualstudio.com/MyFirstProject/_git/new-contoso-repo
```

(And then remove the temporary directory `old-contoso-repo.git`.)

## Time tracking

For time tracking, we use [Git Time Metric](https://github.com/git-time-metric/gtm), version 1.3.5.
We started using it on August 26th 2018.

To push its data to remote repository, `git pushgtm` has to be run.
It's incorporated in script `/scripts/push_all.cmd`, so that it doesn't have to be run manually.

Also, it works only via editor plugins, so they must be installed before it starts tracking time.
For Visual Studio, there is no official plugin, so we wrote [a simple one](https://jjones.visualstudio.com/gtm-visualstudio-plugin) ourselves.

We run `gtm init` not only inside the root directory of the project, but also inside folders of our forked dependencies.
This adds a line into their `.gitignore` files and we tag it with `[gtm]`.

## Submodules

**TODO: Use [Subrepos](https://github.com/ingydotnet/git-subrepo/blob/master/Intro.pod) instead?**
