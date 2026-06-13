F=tsp11301.ts
ffprobe -v error -select_streams v:0 -show_entries packet=pts_time -of default=noprint_wrappers=1:nokey=1 $F | head -n 1
threefive $F

