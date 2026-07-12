fetch("/api/health")
  .then((r) => r.json())
  .then((d) => {
    document.getElementById("status").textContent = `${d.status} (v${d.version})`;
  })
  .catch(() => {
    document.getElementById("status").textContent = "unreachable";
  });
