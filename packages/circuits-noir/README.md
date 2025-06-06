<p align="center">
    <h1 align="center">
        Semaphore Noir circuits
    </h1>
    <p align="center">Semaphore circuits in Noir to generate and verify zero-knowledge proofs.</p>
</p>

<p align="center">
    <a href="https://github.com/semaphore-protocol">
        <img src="https://img.shields.io/badge/project-Semaphore-blue.svg?style=flat-square">
    </a>
    <a href="https://github.com/semaphore-protocol/semaphore/tree/main/packages/circuits/LICENSE">
        <img alt="NPM license" src="https://img.shields.io/npm/l/%40semaphore-protocol%2Fcircuits?style=flat-square">
    </a>
    <a href="https://www.npmjs.com/package/@semaphore-protocol/circuits">
        <img alt="NPM version" src="https://img.shields.io/npm/v/@semaphore-protocol/circuits?style=flat-square" />
    </a>
    <a href="https://npmjs.org/package/@semaphore-protocol/circuits">
        <img alt="Downloads" src="https://img.shields.io/npm/dm/@semaphore-protocol/circuits.svg?style=flat-square" />
    </a>
</p>

<div align="center">
    <h4>
        <a href="https://github.com/semaphore-protocol/semaphore/blob/main/CONTRIBUTING.md">
            👥 Contributing
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://github.com/semaphore-protocol/semaphore/blob/main/CODE_OF_CONDUCT.md">
            🤝 Code of conduct
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://github.com/semaphore-protocol/semaphore/contribute">
            🔎 Issues
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://semaphore.pse.dev/telegram">
            🗣️ Chat &amp; Support
        </a>
    </h4>
</div>

---

_Note_: The Noir circuit is parameterized by `MAX_DEPTH`; replace its value in `src/main.nr` to create a circuit for a different max tree depth.

## Compilation

```
nargo compile
```

## Run Noir tests

```
nargo test
```
