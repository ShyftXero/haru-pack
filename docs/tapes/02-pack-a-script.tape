# The TL;DR, end to end: a .py file becomes a binary and the binary runs.
Output "docs/media/02-pack-a-script.gif"
Set Shell "bash"
Set FontSize 20
Set Width 1100
Set Height 420
Set Padding 14
Set TypingSpeed 45ms
Set PlaybackSpeed 2.5
Hide
Type "export PS1='$ ' && cd $HARU_DEMO_ROOT/work && clear"
Enter
Show
Type "cat hello.py"
Sleep 400ms
Enter
Sleep 1500ms
Type "haru-pack hello.py"
Sleep 500ms
Enter
Sleep 40s
Type "./hello"
Sleep 400ms
Enter
Sleep 6s
Type "file hello | cut -c1-80"
Sleep 400ms
Enter
Sleep 4s
