# @premierstudio/premier

The script-free npm distribution of the Premier agent flight recorder. The
package selects a platform-specific optional dependency and launches the native
`premier` binary. It does not run install scripts or download remote binaries.

```sh
npm install --global @premierstudio/premier
premier --version
premier demo
```

See [premier.dev/docs/install](https://premier.dev/docs/install) for global,
project-local, and provider-specific recording workflows.
