# What toolchain this machine actually has. Embedded in README's install section.
Output "docs/media/01-doctor.gif"
Set Shell "bash"
Set FontSize 20
Set Width 1100
Set Height 400
Set Padding 14
Set TypingSpeed 45ms
Hide
Type "export PS1='$ ' && cd $HARU_DEMO_ROOT/work && clear"
Enter
Show
Type "haru-pack doctor"
Sleep 500ms
Enter
Sleep 4s
