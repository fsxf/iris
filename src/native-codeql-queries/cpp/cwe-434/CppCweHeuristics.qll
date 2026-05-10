private import cpp

predicate exprContains(Expr outer, Expr inner) {
  outer = inner
  or
  outer.getAChild*() = inner
}

predicate explicitUploadApiName(string name) {
  name =
    [
      "MHD_lookup_connection_value", "FCGX_GetParam", "cgiFormFileName", "cgiFormFileContentType",
      "cgiFormFileSize", "cgiFormFileOpen", "mg_get_http_var", "mg_get_header", "evhttp_find_header"
    ]
}

predicate explicitDiskWriteName(string name) {
  name = ["fopen", "freopen", "open", "creat", "rename"]
}

predicate strongUploadControlName(string name) {
  name =
    [
      "realpath", "canonical", "weakly_canonical", "lexically_normal", "basename",
      "memcmp", "strncmp", "strcmp", "strstr", "magic_buffer", "magic_file"
    ]
}

