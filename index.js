var _ = require('underscore'),
    path = require('path');


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
 *    success_message: '已授权',
 *    failure_message: '请登录'
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

var Acl = function(options,accessControlList){
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
    success_message:'authorized',
    failure_message:'authorize failed'
  };

  
  //set up options
  this.options = _.extend(default_options,options);

  //compile Access Control List
  this.__compiled = permissionCompile(accessControlList);
};

module.exports = Acl;


/** get option
 * @param {String} name - option name
 * @return {String|Function} - option value
 */
Acl.prototype.get = function(name){
  return this.options[name];
};


/** set option
 * @public
 * @param {String} name - option name
 * @param {Object} value - option value
 */
Acl.prototype.set = function(name,value){
  this.options[name] = value;
};


/** register express middleware
 *  ```
 *  var Acl = require('resourceful-acl');
 *  var acl= new Acl(
 *  {
 *    success_message:'authorized',
 *    failure_message:'please login!'
 *  },
 *  accessControlList);
 *  app.use(acl.authorize([callback]));
 *  ```
 *
 *  ### redirect
 *  ```
 *    app.use(acl.authorize({
 *      failure_redirect:'/login',
 *      flash:true,             //it dependent on 'req.flash()'
 *    }));
 *  ```
 *
 *  ##custom Callback
 *
 *  ```
 *  app.use(function(req,res,next){
 *    acl.authorize(function(err,info,status){
 *      if(err){
 *        req.flash('danger',info); //info === failure_message
 *        res.redirect('/login');
 *      }else{
 *        next();
 *      }
 *    })(req,res,next);
 *  });
 *  ```
 *
 *
 *  It will get user roles from 'req.user.role' on default,you also can define a function determine to get the user role.
 *  Then get request method from 'req.method' and get request path from 'req.path'
 *  get check result from `req.acl`
 *
 * @return {Function} return an express middleware
 */
Acl.prototype.authorize = function(option){
  var that = this,
      redirect,
      custom_callback;

  if(option){
    if(_.isObject(option) && option.failure_redirect){
      redirect = option;
    }else if(_.isFunction(option)){
      custom_callback = option;
    }else{
      throw new TypeError('Argument Error: expect an Object or a Function');
    }
  }

  return function(req,res,next){
    var user_role,                                   //角色名
        req_path = path.join(req.baseUrl,req.path),  //请求路径
        req_method = req.method.toLowerCase(),       //请求方法
        result = null,                               //结果
        start_match = Date.now();

    //get user role
    that.get("get_role")(req,function(err,role){
      if(err || role === false){
        user_role = that.get("default"); //默认角色
      }else{
        user_role = role;
      }

      //一个用户拥有多个角色
      if(_.isArray(user_role)){
        //check roles one by one
        for(var i = 0;i < user_role.length; i++){
          result = that.check(user_role[i],req_path,req_method);
          if(result.status === 'allowed' || result.status === 'role_undefined'){
            break;
          }
        }
      }else{
        result = that.check(user_role,req_path,req_method);
      }

      req.acl = result;
      req.acl.times = Date.now() - start_match;
      if(result.status === 'allowed' || result.status === 'not_matched'){
        if(option && custom_callback){
          custom_callback(null,that.get('success_message'),result.status);
        }else{
          next();
        }
      }
      else{
        err= new Error('Unauthorized');
        err.code = 403;
        err.status = result.status;
        err.role = result.role;
        err.resource = result.resource;
        if(option){
          if(redirect){ //跳转
            if(redirect.flash && req.flash){
              if(_.isString(redirect.flash))
                req.flash('danger',redirect.flash);
              else
                req.flash('danger',that.get('failure_message'));
            }
            return res.redirect(303,redirect.failure_redirect);
          }else if(custom_callback){
            return custom_callback(err,that.get('failure_message'),result.status);
          }
        }
        return next(err);
      }
      //end of get_role
    });
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

Acl.prototype.methodIsAllow = function(resource,req_method,role){
  //handle nested resource
  //检查父资源
  if(resource.belongs_to){
    if(isView(req_method)){
      //读操作，必须对父资源有可读权限
      //must have right to view descend resource
      if(this.check(role,toPath(resource.belongs_to),"view").status != "allowed")
        return false;
    }else if(isEdit(req_method) || isDelete(req_method)){
      //must have right to edit descend resource
      if(this.check(role,toPath(resource.belongs_to),"edit").status != "allowed")
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

var methodMap = function(methods){
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

//将资源名转换成正则表达式
var getResourcePath = function(resource){
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

//编译访问控制列表
var permissionCompile = function(assignments){
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
        resourcePath = getResourcePath(resource);
        path = resourcePath.path;
        belongs_to = resourcePath.belongs_to;
        priority = resourcePath.priority;
      }

      _curRes.path = _.isRegExp(path) ? path : new RegExp(path,'i');
      _curRes.name = resource;
      _curRes.methods = methodMap(methods);
      _curRes.belongs_to = belongs_to;
      _curRes.priority = priority;
      compiled[role].resources.push(_curRes);
    }
    compiled[role].resources=_.sortBy(compiled[role].resources,'priority');
  }
  return compiled;
};

Acl.prototype.check = function(role,req_path,req_method){
  var compiled = this.__compiled;
  var parents = compiled[role] && compiled[role].parents; //角色的父类
  var i,result,resources,resource;
  var response = {
    "status":null,           //检查的状态
    "role":role,             //当前检查的角色
    "resource":null,         //匹配的资源
    "path":req_path,         //请求路径
    "method":req_method,     //请求方法
  };

  //check role
  if(!compiled[role]){
    response.status = "role_undefined";  //角色不存在,访问控制列表定义出错
    return response;
  }

  //check parents of role
  if(parents){
    //检查父角色，如果父角色通过则通过
    for(i = 0; i < parents.length; i++){
      result = this.check(parents[i],req_path,req_method);
      if(result.status === "allowed")
        return result;
    }
  }

  //检查定义的资源
  resources = compiled[role].resources;
  for(i = resources.length - 1; i >= 0; i--){
    resource = resources[i];
    if(req_path.search(resource.path) != -1){
      response.resource = resource.name;
      //match the resource

      //检查方法是否允许
      if(this.methodIsAllow(resource,req_method,role)){
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

