export function searchQuery(name) {
  let search = window.location.search;
  let params = new URLSearchParams(search);
  return params.get(name);
}
