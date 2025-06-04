import typescript from "@rollup/plugin-typescript"
import json from "@rollup/plugin-json"
import cleanup from "rollup-plugin-cleanup"
import * as fs from "fs"

const pkg = JSON.parse(fs.readFileSync("./package.json", "utf-8"))
const banner = `/**
 * @module ${pkg.name}
 * @version ${pkg.version}
 * @file ${pkg.description}
 * @copyright Ethereum Foundation ${new Date().getFullYear()}
 * @license ${pkg.license}
 * @see [Github]{@link ${pkg.homepage}}
*/`
export default {
    input: "src/index.ts",
    output: [{ file: pkg.exports.require, format: "cjs", banner, exports: "auto" }],
    external: [...Object.keys(pkg.dependencies), "node:fs", "node:fs/promises", "node:path", "node:os"],
    plugins: [
        typescript({
            tsconfig: "./build.tsconfig.json"
        }),
        cleanup({ comments: "jsdoc" }),
        json()
    ]
}
