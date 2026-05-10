import python

string exprName(Expr e) {
  e instanceof Name and result = e.(Name).getId()
  or
  e instanceof Attribute and result = exprName(e.(Attribute).getObject()) + "." + e.(Attribute).getName()
  or
  not e instanceof Name and
  not e instanceof Attribute and
  result = e.toString()
}

string callName(Call c) {
  result = exprName(c.getFunc())
}

string parameterTypes(Call c) {
  result = concat(int i | exists(c.getArg(i)) | "p" + i.toString(), ";" order by i asc)
}

from Call api
where not api.getLocation().getFile().getRelativePath().matches("%/test/%")
select
  api as callstr,
  "python" as package,
  "module" as clazz,
  callName(api) as func,
  callName(api) + "(" + parameterTypes(api) + ")" as full_signature,
  callName(api) as internal_signature,
  callName(api) as callable_name,
  "false" as is_static,
  api.getLocation().getFile() as file,
  api.getLocation().toString() as location,
  parameterTypes(api) as parameter_types,
  "" as return_type,
  "" as doc
