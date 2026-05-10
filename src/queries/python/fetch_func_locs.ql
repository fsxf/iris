import python

from Function f
select
  f,
  f.getName() as name,
  f.getLocation().getFile() as file,
  f.getLocation().getStartLine() as start_line,
  f.getLocation().getEndLine() as end_line
