# GitHub SSH from ProxSpace

This is a quick guide to configuring Git and SSH authentication for GitHub from ProxSpace.

## Configure Git

Configure your Git email address and username:

```bash
git config --global user.email "You@YourEmail.com"
git config --global user.name "YourUserName"
```

## Generate an SSH key

Use `ssh-keygen` to generate an Ed25519 SSH key pair if you do not already have one:

```bash
ssh-keygen -t ed25519 -C "You@YourEmail.com"
```

Accept the defaults:

```text
Enter file in which to save the key (/pm3/.ssh/id_ed25519):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
```

This creates:

```text
/pm3/.ssh/id_ed25519       # Private key
/pm3/.ssh/id_ed25519.pub   # Public key
```

## Add the public key to GitHub

Display the public key:

```bash
cat /pm3/.ssh/id_ed25519.pub
```

Copy the complete output and add it to your GitHub account under:

**Settings → SSH and GPG keys → New SSH key**

Only the `.pub` file should be added to GitHub. Keep the private key private.

## Test SSH authentication

Test SSH authentication to GitHub using the specified private key, without attempting to open a shell session:

```bash
ssh -i /pm3/.ssh/id_ed25519 -T git@github.com
```

A successful response looks like:

```text
Hi YourUserName! You've successfully authenticated, but GitHub does not provide shell access.
```

## Check the Git remote

Check that the repository remote is configured to use SSH rather than HTTPS:

```bash
git remote -v
```

If it shows HTTPS:

```text
origin  https://github.com/YourUserName/proxmark3.git (fetch)
origin  https://github.com/YourUserName/proxmark3.git (push)
```

Git will still try to authenticate over HTTPS and may prompt for a username/password.

Change the remote to use SSH:

```bash
git remote set-url origin git@github.com:YourUserName/proxmark3.git
```

Check it again:

```bash
git remote -v
```

It should now show:

```text
origin  git@github.com:YourUserName/proxmark3.git (fetch)
origin  git@github.com:YourUserName/proxmark3.git (push)
```

## Push

Git should now use SSH authentication when pushing:

```bash
git push origin <branch-name>
```

For example:

```bash
git push origin feature/my_fab_feature
```
