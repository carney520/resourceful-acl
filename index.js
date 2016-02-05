var _ = require('underscore');

//export acl
module.exports = function(options,permissionAssign){
  if(arguments.length != 2){
    permissionAssign = options;
    options={};
  }
  // default options
  var default_options = {
    //TODO use callback
    get_role:function(req,callback){
      if(req.user && req.user.role)
        callback(null,req.user.role);
      else
        callback(null,false);
    },
    default:'default',
  };
  //set configures
  exports.get_role = options.get_role || default_options.get_role;
  exports.default_role = options.default || default_options.default;
  exports.compiled = permissionCompile(permissionAssign);
  console.log(JSON.stringify(exports.compiled));
  that = exports;

  //middleware for express
  return function(req,res,next){
    var user_role = that.default_role,
        req_path = req.path,
        req_method = req.method.toLowerCase(),
        result = null,
        start_match = Date.now();
    //get user role
    that.get_role(req,function(err,role){
      if(err || role === false){
        user_role = that.default_role;
      }else{
        user_role = role;
      }
    });

    console.log('method:'+req_method +"\n"+
        'path:'+req_path + "\n"+
        'role:'+user_role +"\n"
        );

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

    //no match for resource
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

var exports = module.exports;


var methodIsAllow = function(resource,req_method,resources){
  if(resource.inherit){
    //parents denied
    if(!methodIsAllow(_.findWhere(resources,{name: resource.inherit}),req_method,resources))
      return false;
  }

  if(_.isArray(resource.methods))
    return  _.includes(resource.methods,req_method);
  else if(resource.methods === '*')
    return true;
  else if(resource.methods === null)
    return false;
};

exports.methodMap = function(methods){
  var map = {
    view:['get'],
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

var permissionCompile = function(assignments){
  var compiled = {};
  for(var role in assignments){
    var roleParent = assignments[role].extends || null;
    var roleResources = assignments[role].extends ? assignments[role].resources : assignments[role];

    compiled[role]={};
    compiled[role].resources=[];
    compiled[role].parents = roleParent;


    for(var resource in roleResources){
      var _curRes = {};
      var _res = roleResources[resource] || {};
      var path = _res.path || "";
      var methods =_res.methods || _res;
      var inherit  =_res.inherit || null;
      // sub-resource match before his parent
      var priority = 1;

      if(path === ""){
        var pathVariable = '([^/]+?/?)?';
        if(resource === 'index'){
          path = '^/$';
        }
        else{
          var resources = resource.split('_');
          if(resources.length == 1){
            path += '/'+resource + "/?"+ pathVariable +pathVariable;
          }else{
            //nested resource，another name is resource inheritance
            for(var i=0;i < resources.length; i++){
              path += '/'+resources[i] + "/?"+ pathVariable;
            }
            //support /users/:id/posts/:postid/edit
            path += pathVariable;
            //setup inherit
            inherit = _.take(resources,resources.length - 1).join('_');
          }
          path = "^" + path + "$";
          priority = resources.length;
        }
      }
      _curRes.name = resource;
      _curRes.path = new RegExp(path,'i');
      _curRes.methods = exports.methodMap(methods);
      _curRes.inherit = inherit;
      _curRes.priority = priority;
      compiled[role].resources.push(_curRes);
    }
    compiled[role].resources=_.sortBy(compiled[role].resources,'priority');
  }
  return compiled;
};

exports.check = function(role,req_path,req_method){
  var compiled = exports.compiled;
  var parents = compiled[role] && compiled[role].parents;
  var i,result,resources,resource;
  var response = {
    "status":null,
    "role":role,
    "resource":null
  };

  //check role
  if(!compiled[role]){
    response.status = "role_non_existend";
    return response;
  }

  //check parents of role
  if(parents){
    for(i = 0; i < parents.length; i++){
      result = exports.check(parents[i],req_path);
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
      console.log('match path' + resource.path);
      console.log('match resource: ' +resource.name);
      console.log('request path' + req_path);

      if(methodIsAllow(resource,req_method,resources)){
        //allowed
        console.log('allowed');
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

