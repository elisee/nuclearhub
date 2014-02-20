module.exports = (grunt) ->
  grunt.loadNpmTasks 'grunt-contrib-jade'
  grunt.loadNpmTasks 'grunt-contrib-stylus'
  grunt.loadNpmTasks 'grunt-contrib-coffee'
  grunt.loadNpmTasks 'grunt-cson'
  grunt.loadNpmTasks 'grunt-contrib-uglify'
  grunt.loadNpmTasks 'grunt-contrib-watch'

  grunt.initConfig
    jade:
      compile:
        options:
          client: true
          processName: (filename) -> filename.substring 'assets/templates/'.length, filename.indexOf('.jade')
          compileDebug: false
        files:
          'assets/templates/templates.js': [ 'assets/templates/**/*.jade' ]
    stylus:
      compile:
        files: [
          expand: true
          cwd: 'assets/stylesheets'
          src: [ '**/*.styl' ]
          dest: 'public/css'
          ext: '.css'
        ]
    coffee:
      compile:
        files: [
          expand: true
          cwd: 'assets/coffeescripts'
          src: [ '**/*.coffee' ]
          dest: 'public/js'
          ext: '.js'
        ]
    cson:
      i18n:
        expand: true
        cwd: 'assets/locales'
        src: [ '**/*.cson' ]
        dest: 'public/locales'
        ext: '.json'
    uglify:
      jadeRuntime:
        files:
          'public/js/templates.js': [ 'node_modules/jade/runtime.js', 'assets/templates/templates.js' ]
      compile:
        files: [
          expand: true
          cwd: 'public/js'
          src: [ '**/*.js' ]
          dest: 'public/js'
          ext: '.js'
        ]
    watch:
      templates:
        files: [ 'assets/templates/**/*.jade' ]
        tasks: [ 'jade', 'uglify:jadeRuntime' ]
      stylesheets:
        files: [ 'assets/stylesheets/**/*.styl' ]
        tasks: [ 'stylus' ]
      scripts:
        files: [ 'assets/coffeescripts/**/*.coffee' ]
        tasks: [ 'coffee' ]
      i18n:
        files: [ 'assets/locales/**/*.cson' ]
        tasks: [ 'cson:i18n' ]  
  
  grunt.registerTask 'default', [ 'jade', 'stylus', 'coffee', 'cson', 'uglify' ]
  grunt.registerTask 'dev', [ 'jade', 'stylus', 'coffee', 'cson', 'uglify:jadeRuntime', 'watch' ]
