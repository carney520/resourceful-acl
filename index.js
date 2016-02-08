var _ = require('underscore');

/** program entrance,it will initialize Access Control list,and set up options
 * 
 *   var acl = require('resourceful-acl');
 *   var options = {
 *    //declare how to get user's role
 *    //role can be a string,like 'reader',as well as Array,for example:['reader','other']
 *    get_role:function(req,callback){
 *      callback(null,req.session.user.role);
 *    },
 *    //if role non-existend,set 'reader' as default role
 *    default:'reader'
 *   };
 *   
 *   var accessControlList = {
 *     'reader':{ //define role
 *       'index':'get',  //define resource,the mean is "allow reader to GET /"
 *       'posts':'view', //'view' is a shorthand for ['get','head','options']
 *                       //'posts' represent  'posts' resources(RESTful),it mean that allow 'reader' to 'view' the following request path:
 *                         // /posts       => collection path
 *                         // /posts/:id   => member  path
 *                         // /posts/:id/*  => member method
 *       'posts_images':'view', //'posts_images' are nested resources, it represent following request path:
 *                                // /posts/:id/images
 *                                // /posts/:id/images/:image_id
 *                                // /posts/:id/images/:image_id/*
 *       'customize_resource':{   // you can customize your resource
 *         path: /^\/customize_resource\/?(\d+?\/?)?$/     // a regexp, it will match following request path
 *                                                   // /customize_resource
 *                                                   // /customize_resource/
 *                                                   // /customize_resource/{Number}
 *                                                   // /customize_resource/{Number}/
 *         methods:['get','post']
 *       }
 *     },
 *     'editor':{
 *       extends:"reader",  //'editor' inherit from 'reader',so 'editor' can view 'index' and 'posts'
 *       resources:{        //if you defined 'extends' attribute, you must defined resources in 'resources' attribute,like this
 *         'posts':["edit","delete"],  //allow 'editor' to edit and delete posts. "edit" is a shorthand for ['put','post','patch']
 *         'posts_images':["edit","delete"]
 *         'contributes':'*'           //allow all methods
 *       }
 *     }
 *   };
 *
 *   acl(options,accessControlList);
 *   app.use(acl.authorize());
 *
 * @param {Object} options - options to control program behavior
 * @param {Object} accessControlList - declare access control list
 * @return {Object} some methods
 */

module.exports = function(options,accessControlList){
  if(arguments.length != 2){
    accessControlList = options;
    options={};
  }
  // default options
  var default_options = {
    get_role:function(req,callback){
      if(req.user && req.user.role)
        callback(null,req.user.role);
      else
        callback(null,false);
    },
    default:'default',
  };

  //set up options
  exports.options = {};
  exports.options.get_role = options.get_role || default_options.get_role;
  exports.options.default  = options.default  || default_options.default;

  //compile Access Control List
  exports.__compiled = exports.permissionCompile(accessControlList);

  return exports;
};

var exports = module.exports;


/** get option
 * @param {String} name - option name
 * @return {String|Function} - option value
 */
exports.get = function(name){
  return this.options[name];
};


/** set option
 * @public
 * @param {String} name - option name
 * @param {Object} value - option value
 */
exports.set = function(name,value){
  this.options[name] = value;
};


/** register express middleware
 *  ```
 *  var acl = require('resourceful-acl');
 *  acl(options,accessControlList);
 *  app.use(acl.authorize());
 *  ```
 *
 *  It will get user roles from 'req.user.role' on default,you also can define a function determine how to get the user role.
 *  Then get request method from 'req.method' and get request path from 'req.path'
 *  //TODO
 *  req.acl
 *  not_matched
 *
 * @return {Function} return an express middleware
 */
exports.authorize = function(){
  var that = exports;
  return function(req,res,next){
    var user_role = that.get("default"),
        req_path = req.path,
        req_method = req.method.toLowerCase(),
        result = null,
        start_match = Date.now();
    //get user role
    that.get("get_role")(req,function(err,role){
      if(err || role === false){
        user_role = that.get("default");
      }else{
        user_role = role;
      }
    });

    if(_.isArray(user_role)){
      //check roles one by one
      for(var i = 0;i < user_role.length; i++){
        result = that.check(user_role[i],req_path,req_method);
        if(result.status === 'allowed' || result.status === 'role_non_existend'){
          break;
        }
      }
    }else{
      result = that.check(user_role,req_path,req_method);
    }

    req.acl = result;
    req.acl.times = (Date.now() - start_match)/1000;
    if(result.status === 'allowed' || result.status === 'not_matched'){
      next();
    }
    else{
      var err= new Error('Unauthorized');
      err.code = 403;
      err.status = result.status;
      err.role = result.role;
      err.resource = result.resource;
      return next(err);
    }
  };
};

var isEdit = function(method){
  return _.includes(["post","patch","put"],method) || method === "edit";
};

var isView = function(method){
  return _.includes(["get","head","options"],method) || method === "view";
};

var isDelete = function(method){
  return method === "delete";
};

var toPath = function(resource){
  var resources = resource.split("_");
  var path = "";
  for(var i = 0; i< resources.length; i++){
    path += "/" + resources[i] +"/:id";
  }
  return path;
};

var methodIsAllow = function(resource,req_method,role){
  //handle nested resource
  if(resource.belongs_to){
    if(isView(req_method)){
      //must have right to view descend resource
      if(exports.check(role,toPath(resource.belongs_to),"view").status != "allowed")
        return false;
    }else if(isEdit(req_method) || isDelete(req_method)){
      //must have right to edit descend resource
      if(exports.check(role,toPath(resource.belongs_to),"edit").status != "allowed")
        return false;
    }
  }


  if(_.isArray(resource.methods)){
    if(req_method === "edit"){
      return _.any(resource.methods,isEdit);
    }
    else if(req_method === "view"){
      return _.includes(resource.methods,"get");
    }
    else
      return  _.includes(resource.methods,req_method);
  }
  else if(resource.methods === '*')
    return true;
  else if(resource.methods === null)
    return false;
};

exports.methodMap = function(methods){
  var map = {
    view:['get','head','options'],
    edit:['put','post','patch'],
    delete:['delete']
  };

  if(methods === '*')
    return methods;
  else if(_.isString(methods)){
    return map[methods] || [methods];
  }else if(_.isArray(methods)){
    return _.flatten(_.map(methods,function(value){
      return map[value] || value;
    }));
  }else{
    return null;
  }
};

exports.getResourcePath = function(resource){
  var path = "";
  var belongs_to = null;
  var priority = 1;

  var pathVariable = '([^/]+?/?)?';
  var slash = "/?";
  if(resource === "index"){
    path = '^/$';
  }else{
    var resources = resource.split('_');
    if(resources.length === 1){
      path = '/' + resource + slash + pathVariable + pathVariable;
    }else{
      for(var i = 0; i <resources.length; i++){
        path += '/' + resources[i] + slash + pathVariable;
      }
      path += pathVariable;
      belongs_to = _.take(resources,resources.length - 1).join('_');
      priority = resources.length;
    }
    path = "^" + path + "$";
  }
  return {
    path:path,
    belongs_to:belongs_to,
    priority:priority
  };
};

exports.permissionCompile = function(assignments){
  var compiled = {};
  for(var role in assignments){
    var roleParent = assignments[role].extends || null;
    var roleResources = assignments[role].extends ? assignments[role].resources : assignments[role];

    //conver roleParent to array
    if(roleParent && ! _.isArray(roleParent)) roleParent = [roleParent];

    compiled[role]={};
    compiled[role].resources=[];
    compiled[role].parents = roleParent;


    for(var resource in roleResources){
      var _curRes = {};
      var _res = roleResources[resource] || {};
      var path = _res.path || null;
      var methods =_res.methods || _res;
      var belongs_to  =_res.belongs_to || null;
      // sub-resource match before his belongs_to
      var priority = 1;

      if(!path){
        resourcePath = this.getResourcePath(resource);
        path = resourcePath.path;
        belongs_to = resourcePath.belongs_to;
        priority = resourcePath.priority;
      }

      _curRes.path = _.isRegExp(path) ? path : new RegExp(path,'i');
      _curRes.name = resource;
      _curRes.methods = this.methodMap(methods);
      _curRes.belongs_to = belongs_to;
      _curRes.priority = priority;
      compiled[role].resources.push(_curRes);
    }
    compiled[role].resources=_.sortBy(compiled[role].resources,'priority');
  }
  return compiled;
};

exports.check = function(role,req_path,req_method){
  var compiled = exports.__compiled;
  var parents = compiled[role] && compiled[role].parents;
  var i,result,resources,resource;
  var response = {
    "status":null,
    "role":role,
    "resource":null,
    "path":req_path,
    "method":req_method,
  };

  //check role
  if(!compiled[role]){
    response.status = "role_non_existend";
    return response;
  }

  //check parents of role
  if(parents){
    for(i = 0; i < parents.length; i++){
      result = exports.check(parents[i],req_path,req_method);
      if(result.status === "allowed")
        return result;
    }
  }

  resources = compiled[role].resources;
  for(i = resources.length - 1; i >= 0; i--){
    resource = resources[i];
    if(req_path.search(resource.path) != -1){
      response.resource = resource.name;
      //match the resource

      if(methodIsAllow(resource,req_method,role)){
        //allowed
        response.status = "allowed";
        return response;
      }
      //match but no allowed
      response.status = "denied";
      return response;
    }
  }

  //no match any resource
  response.status = 'not_matched';
  return response;
};

