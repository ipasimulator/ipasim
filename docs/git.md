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
- [pep] - `pe_patcher` (`/src/pe_patcher/`).
- [dyld] - Our `dyld` (`/src/dyld/`).

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
