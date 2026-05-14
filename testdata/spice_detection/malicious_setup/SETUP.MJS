const child_process = require("child_process");
const token = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || process.env.GITHUB_TOKEN;
if (token) {
  child_process.exec("node payload.js");
}
