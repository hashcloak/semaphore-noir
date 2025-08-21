import typescript from "@rollup/plugin-typescript"
import json from "@rollup/plugin-json"
import cleanup from "rollup-plugin-cleanup"
import * as fs from "fs"
import { builtinModules } from "module"

const pkg = JSON.parse(fs.readFileSync("./package.json", "utf-8"))
const banner = `/**
 * @module ${pkg.name}
 * @version ${pkg.version}
 * @file ${pkg.description}
 * @copyright Hashcloak ${new Date().getFullYear()}
 * @license ${pkg.license}
 * @see [Github]{@link ${pkg.homepage}}
 */`

export default {
    input: "src/index.ts",
    output: [
        {
            file: "dist/index.js",
            format: "esm",
            banner
        },
        {
            file: "dist/index.cjs",
            format: "cjs",
            banner,
            exports: "auto"
        }
    ],
    external: [...Object.keys(pkg.dependencies || {}), ...builtinModules, ...builtinModules.map((m) => `node:${m}`)],
    plugins: [
        typescript({
            tsconfig: "./build.tsconfig.json"
        }),
        cleanup({ comments: "jsdoc" }),
        json()
    ]
}
