//Define the include function for absolute file name
global.base_dir = __dirname;
global.abs_path = function(path) {
	return base_dir + path;
}
global.include = function(file) {
	return require(abs_path('/' + file));
}
//base_dir is the new variable that represents the directory name of the current module
//abs_path is a function that takes the path as an argument and concatenates it with the base_dir variable, giving the absolute path 
//include is a function that takes the absolute path and concatenates it with the file name passed in as an argument, resulting in the absolute path of the input file 