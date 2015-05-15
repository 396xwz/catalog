# Catalog App 

## Fetch the Source Code and VM Configuration

**Windows:** Use the Git Bash program (installed with Git) to get a Unix-style terminal.  
**Other systems:** Use your favorite terminal program.


## Run the virtual machine!

Using the terminal, change directory to Catalog, then type **vagrant up** to launch your virtual machine. Type **vagrant provision** (first time).


## Running the Catalog App
Once it is up and running, type **vagrant ssh**. This will log your terminal into the virtual machine, and you'll get a Linux shell prompt. When you want to log out, type **exit** at the shell prompt.  To turn the virtual machine off (without deleting anything), type **vagrant halt**. If you do this, you'll need to run **vagrant up** again before you can log into it.


Now that you have Vagrant up and running type **vagrant ssh** to log into your VM.  change to the /vagrant directory by typing **cd /vagrant**. This will take you to the shared folder between your virtual machine and host machine.

Type **ls** to ensure that you are inside the directory that contains project.py, database_setup.py, and two directories named 'templates' and 'static'

Now type **python database.py** to initialize the database.

Type **python init_data.py** to populate the database with catalog items. (Optional)

Type **python application.py** to run the app server. In your browser visit **http://localhost:8080** to view the Catalog app.  You should be able to register, login, view, add, edit, and delete items and categories.
