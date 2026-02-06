---
layout: post
title: "VS Code Remote SSH `code` Command"
subtitle: "Enable CLI in Remote SSH"
category: blog
tags: development terminal vscode translation
---

When developing on a server via VS Code Remote SSH, a separate terminal (outside the
integrated terminal) does not automatically support the `code` command to open a VS Code
window. In such environments, commands like `git commit` also default to launching `vim`.

This note outlines how to enable the `code` command when connected to a server over SSH.

<!--more-->

* this unordered seed list will be replaced by the toc
{:toc}

## Prerequisites

* `zsh`
* `VSCode Remote-SSH` (A remote session must be open to use the `code` command.)

## Command Installation

Save the following script as a file named `code` in one of the folders in `$PATH` (e.g. `~/.bin`).

If you are not sure which folders are in `$PATH`, check with `echo $PATH`.
{:.note}

### For ZSH

```shell
# file: "$PATH/code"
#! /usr/bin/env zsh

local max_retry=10

for i in {1..$max_retry}
do
    local script=$(echo ~/.vscode-server/bin/*/bin/remote-cli/code(*oc[$i]N))
    if [[ -z ${script} ]]
    then
        echo "VSCode remote script not found"
        exit 1
    fi
    local socket=$(echo /run/user/$UID/vscode-ipc-*.sock(=oc[$i]N))
    if [[ -z ${socket} ]]
    then
        echo "VSCode IPC socket not found"
        exit 1
    fi
    export VSCODE_IPC_HOOK_CLI=${socket}
    ${script} $@ > /dev/null 2>&1
    if [ "$?" -eq "0" ]; then
        exit 0
    fi
done

echo "Failed to find valid VS Code window"
```

### For Bash

```shell
#! /bin/bash

max_retry=10

for i in $(seq 1 $max_retry)
do
    recent_folder=$(ls ~/.vscode-server/bin/ -t | head -n$i)
    script=$(echo ~/.vscode-server/bin/$recent_folder/bin/remote-cli/code)
    if [[ -z ${script} ]]
    then
        echo "VSCode remote script not found"
        exit 1
    fi
    socket=$(ls /run/user/$UID/vscode-ipc-* -t | head -n$i)
    if [[ -z ${socket} ]]
    then
        echo "VSCode IPC socket not found"
        exit 1
    fi
    export VSCODE_IPC_HOOK_CLI=${socket}
    ${script} $@
    if [ "$?" -eq "0" ]; then
        exit 0
    fi
done

echo "Failed to find valid VS Code window"
```

When using the `code` command in an SSH terminal, at least one `VSCode Remote - SSH` session
must be connected.
{:.note title="Warning"}

## Git Configuration

Use the following command to set VS Code as Git's default editor.

```shell
git config --global core.editor "code --wait"
```

If this note was helpful, consider sharing it with others working over SSH.
