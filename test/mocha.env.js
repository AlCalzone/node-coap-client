// Makes ts-node ignore warnings, so mocha --watch does work
process.env.TS_NODE_IGNORE_WARNINGS = "TRUE";
// Sets the correct tsconfig for testing
process.env.TS_NODE_PROJECT = "tsconfig.json";

// Don't silently swallow unhandled rejections
process.on("unhandledRejection", (e) => {
	throw e;
})
