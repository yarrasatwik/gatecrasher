const boot = async () => {
  const m = await import("./flags-abc.js");
  m.start();
};
boot();
