import cpp

predicate isLikelyProjectFile(File f) {
  not f.getAbsolutePath().matches("%/.miniconda3/%") and
  not f.getAbsolutePath().matches("%/sysroot/%") and
  not f.getAbsolutePath().matches("%/usr/include/%") and
  not f.getAbsolutePath().matches("%/usr/lib/%") and
  not f.getAbsolutePath().matches("%/include/c++/%")
}

from Function f
where
  f.fromSource() and
  f.hasDefinition() and
  isLikelyProjectFile(f.getLocation().getFile()) and
  not f.getLocation().getFile().getRelativePath().matches("%/test/%")
select
  f,
  "cpp" as package,
  "function" as clazz,
  f.getName() as func,
  f.getLocation().getFile() as file,
  f.getLocation().getStartLine() as start_line,
  f.getLocation().getEndLine() as end_line
