"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolvePath = void 0;
const resolvePath = (options) => {
    //remove leading and trailing slash from options.directory
    const directory = options.directory ? options.directory.replace(/^\/|\/$/g, "") : "";
    return options.directory ? `${directory}/${options.filename}` : `${options.filename}`;
};
exports.resolvePath = resolvePath;
