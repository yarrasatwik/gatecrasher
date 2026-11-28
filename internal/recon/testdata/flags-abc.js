// flags chunk
import flagsmith from "flagsmith";

const options = {
  environmentID: "AbCd3fGhJk5mNpQr7StUvW",
  api: "{{API}}",
};
export const start = () => flagsmith.init(options);
