Clap is a rust framework used in designing command-line applications. There are 2 ways to use clap, and I'm using only one in this application. In this project, I have a file called `args.rs`, which contains `structs` and `enums` that define the command/argument structure of the command line application. 

To define commands and arguments for a program, create a struct. The fields of the struct may define either commands or arguments; You can define commands or arguments using [outer attributes](https://doc.rust-lang.org/reference/attributes.html).  The attributes in question are `#[command(...)]` and `#[arg(...)]`.

To create a command/subcommand, you'll need to define an enum containing the 

