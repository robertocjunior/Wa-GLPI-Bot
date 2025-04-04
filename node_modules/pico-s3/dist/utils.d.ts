import { S3GetOptions, S3UploadOptions } from "./types";
export declare const resolvePath: (options: S3GetOptions | S3UploadOptions | {
    filename: string;
    directory?: string;
}) => string;
