import { generateFiles } from "fumadocs-openapi";
import { createOpenAPI } from "fumadocs-openapi/server";

const server = createOpenAPI({
  input: ["./better-auth.json"],
});

async function main() {
  await generateFiles({
    input: server,
    output: "./content/docs/reference/openapi",
    per: "tag",
    beforeWrite(files) {
      if (files.length === 0) {
        throw new Error(
          "No OpenAPI pages generated. The schema must declare top-level tags.",
        );
      }
    },
  });

  console.log("OpenAPI files generated successfully!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
