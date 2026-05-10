import cpp

predicate isLikelyProjectFile(File f) {
  not f.getAbsolutePath().matches("%/.miniconda3/%") and
  not f.getAbsolutePath().matches("%/sysroot/%") and
  not f.getAbsolutePath().matches("%/usr/include/%") and
  not f.getAbsolutePath().matches("%/usr/lib/%") and
  not f.getAbsolutePath().matches("%/include/c++/%")
}

string parameterNames(Function f) {
  result = concat(int i | exists(f.getParameter(i)) | f.getParameter(i).getName(), ";" order by i asc)
}

string parameterTypes(Function f) {
  result = concat(int i | exists(f.getParameter(i)) | f.getParameter(i).getType().toString(), ";" order by i asc)
}

string functionSignature(Function f) {
  result = f.getName() + "(" + parameterNames(f) + ")"
}

from FunctionCall api, Function target
where
  api.getTarget() = target and
  isLikelyProjectFile(api.getLocation().getFile()) and
  not api.getLocation().getFile().getRelativePath().matches("%/test/%")
select
  api as callstr,
  "cpp" as package,
  "function" as clazz,
  target.getName() as func,
  functionSignature(target) as full_signature,
  target.getQualifiedName() as internal_signature,
  target.getName() as callable_name,
  "false" as is_static,
  api.getLocation().getFile() as file,
  api.getLocation().toString() as location,
  parameterTypes(target) as parameter_types,
  "" as return_type,
  "" as doc
