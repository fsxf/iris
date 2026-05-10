import python

string parameterNames(Function f) {
  result = concat(int i | exists(f.getArg(i)) | f.getArgName(i), ";" order by i asc)
}

from Function f, Parameter p
where
  f.getAnArg() = p and
  not f.getLocation().getFile().getRelativePath().matches("%/test/%")
select
  p as parameter,
  "python" as package,
  "module" as clazz,
  f.getQualifiedName() as func,
  f.getQualifiedName() + "(" + parameterNames(f) + ")" as full_signature,
  f.getLocation().getFile() as file,
  p.getLocation().toString() as location,
  parameterNames(f) as parameter_types,
  "" as return_type,
  "" as doc
