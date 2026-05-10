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

string functionSignature(Function f) {
  result = f.getName() + "(" + parameterNames(f) + ")"
}

from Function f, Parameter p
where
  f.fromSource() and
  f.hasDefinition() and
  f.getAParameter() = p and
  isLikelyProjectFile(f.getLocation().getFile()) and
  not f.getLocation().getFile().getRelativePath().matches("%/test/%")
select
  p as parameter,
  "cpp" as package,
  "function" as clazz,
  f.getName() as func,
  functionSignature(f) as full_signature,
  f.getLocation().getFile() as file,
  p.getLocation().toString() as location,
  parameterNames(f) as parameter_types,
  "" as return_type,
  "" as doc
