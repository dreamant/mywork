<?php

/** 
 +---------------------------------------------------------- 
 * Name..: 自用小框架 simpleLZF v2.0
 +---------------------------------------------------------- 
 * Author: 李智峰
 * Date..: 2014.2
 +---------------------------------------------------------- 
 * Email.: 59182690@qq.com
 +---------------------------------------------------------- 
 */
 
SESSION_START();
session_set_cookie_params(43200);
header("Content-Type:text/html;charset=utf-8");
date_default_timezone_set('PRC');
error_reporting(E_ERROR|E_STRICT);

//require(APP.'config.php');

//配置了数据库
if(isset($db_config)){
}

//函数库

//0 返回IP地址 1 返回IPV4地址数字
function get_client_ip($type = 0) {
	if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $arr    =   explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $pos    =   array_search('unknown',$arr);
        if(false !== $pos) unset($arr[$pos]);
        $ip     =   trim($arr[0]);
    }elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
        $ip     =   $_SERVER['HTTP_CLIENT_IP'];
    }elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip     =   $_SERVER['REMOTE_ADDR'];
    }
	$long = ip2long($ip);
    $ip   = $long ? array($ip, $long) : array('0.0.0.0', 0);
    return $ip[$type];
}

function redirect($url, $time=0){
	header('Location: '.$url);
}
function toDate($time, $format = 'Y-m-d H:i:s') {
	if (empty ( $time )) {
		return '';
	}
	$format = str_replace ('#',':', $format );
	return date ($format, $time );
}

function import($name = ''){
	static $_d = array();
	$filename = dirname(__FILE__).'/class/'.$name.'.php';
	if (!isset($_d[$filename])) {
		if(file_exists($filename)){
			require $filename;
		}
        $_d[$filename] = true;
	}
	return $_d[$filename];
}

/** 
 +---------------------------------------------------------- 
 * 字符串截取，支持中文和其他编码 
 +---------------------------------------------------------- 
 * @param string $str 需要转换的字符串 
 * @param string $start 开始位置 
 * @param string $length 截取长度 
 * @param string $charset 编码格式 
 * @param string $suffix 截断显示字符 
 +---------------------------------------------------------- 
 * @return string 
 +---------------------------------------------------------- 
 */ 
function msubstr($str, $start=0, $length, $charset="utf-8", $suffix=true){  
    if(function_exists("mb_substr")){   
    if($suffix)   
      return mb_substr($str, $start, $length, $charset)."...";  
      else  
      return mb_substr($str, $start, $length, $charset);   
       }  
    elseif(function_exists('iconv_substr')) {  
        if($suffix)   
       return iconv_substr($str,$start,$length,$charset)."...";  
       else  
       return iconv_substr($str,$start,$length,$charset);  
    }  
    $re['utf-8']   = "/[\x01-\x7f]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xff][\x80-\xbf]{3}/";  
    $re['gb2312'] = "/[\x01-\x7f]|[\xb0-\xf7][\xa0-\xfe]/";  
    $re['gbk']    = "/[\x01-\x7f]|[\x81-\xfe][\x40-\xfe]/";  
    $re['big5']   = "/[\x01-\x7f]|[\x81-\xfe]([\x40-\x7e]|\xa1-\xfe])/";  
    preg_match_all($re[$charset], $str, $match);  
    $slice = join("",array_slice($match[0], $start, $length));  
    if($suffix) return $slice."…";  
    return $slice;  
}


//加密解密
function _encrypt($txt,$key = 'lzf'){
srand((double)microtime() * 1000000);
$encrypt_key = md5(rand(0,32000));
$ctr = 0;
$tmp = '';
for($i = 0;$i<strlen($txt);$i++) {
$ctr = $ctr == strlen($encrypt_key) ? 0 : $ctr;
$tmp .= $encrypt_key[$ctr].($txt[$i]^$encrypt_key[$ctr++]);
}
return base64_encode(_key($tmp,$key));
}

function _key($txt,$encrypt_key) {
$encrypt_key = md5($encrypt_key);
$ctr = 0;
$tmp = '';
for($i = 0; $i < strlen($txt); $i++) {
$ctr = $ctr == strlen($encrypt_key) ? 0 : $ctr;
$tmp .= $txt[$i] ^ $encrypt_key[$ctr++];
}
return $tmp;
}

function _decrypt($txt,$key = 'lzf'){
$txt = _key(base64_decode($txt),$key);
$tmp = '';
for($i = 0;$i < strlen($txt); $i++) {
$md5 = $txt[$i];
$tmp .= $txt[++$i] ^ $md5;
}
return $tmp;
}

/**
 * Cookie 设置、获取、删除
 */
function cookie($name, $value='', $option=null) {
    $config = array(
        'prefix' => '', // cookie 名称前缀
        'expire' => 0, // cookie 保存时间
        'path'   => '/', // cookie 保存路径
        'domain' => '', // cookie 有效域名
    );
    if(!empty($option)) {
        if (is_numeric($option))
            $option = array('expire' => $option);
        elseif (is_string($option))
            parse_str($option, $option);
        $config = array_merge($config, array_change_key_case($option));
    }
    // 清除指定前缀的所有cookie
    if (is_null($name)) {
        if (empty($_COOKIE))
            return;
        // 要删除的cookie前缀，不指定则删除config设置的指定前缀
        $prefix = empty($value) ? $config['prefix'] : $value;
        if (!empty($prefix)) {// 如果前缀为空字符串将不作处理直接返回
            foreach ($_COOKIE as $key => $val) {
                if (0 === stripos($key, $prefix)) {
                    setcookie($key, '', time() - 3600, $config['path'], $config['domain']);
                    unset($_COOKIE[$key]);
                }
            }
        }
        return;
    }
    $name = $config['prefix'].$name;
    if ('' === $value) {
        return isset($_COOKIE[$name]) ? json_decode(MAGIC_QUOTES_GPC?stripslashes($_COOKIE[$name]):$_COOKIE[$name]) : null; // 获取指定Cookie
    } else {
        if (is_null($value)) {
            setcookie($name, '', time() - 3600, $config['path'], $config['domain']);
            unset($_COOKIE[$name]); // 删除指定cookie
        } else {
            // 设置cookie
            $value  = json_encode($value);
            $expire = !empty($config['expire']) ? time() + intval($config['expire']) : 0;
            setcookie($name, $value, $expire, $config['path'], $config['domain']);
            $_COOKIE[$name] = $value;
        }
    }
}

//函数库结束

defined('APP_PATH') or define('APP_PATH', dirname($_SERVER['SCRIPT_FILENAME']).'/');
if(!defined('SITE_URL')){
	$host = trim($_SERVER['HTTP_HOST']);
	if (count(explode('.', $host)) > 2)
		define('SITE_URL', 'http://'.$host.'/');
	else
		define('SITE_URL', 'http://www.'.$host.'/');
}


$url = '';
if(isset($_SERVER['PATH_INFO'])) $uri = $_SERVER['PATH_INFO'];
elseif(isset($_SERVER['ORIG_PATH_INFO'])) $uri = $_SERVER['ORIG_PATH_INFO'];
elseif(isset($_SERVER['QUERY_STRING'])){ 
  $url = explode('&',$_SERVER['QUERY_STRING']);
  $url = $url[0];
}
render_url();
function render_url(){
	global $url;
	if(strpos($url,'.'))return;
	if($_SERVER['QUERY_STRING'])return;
	if(substr($url,-1)=='/')return;
	if($url =='')return;
	header("HTTP/1.1 301 Moved Permanently");
	header ('Location:'.$_SERVER['REQUEST_URI'].'/');
	exit(0);
}

if(get_magic_quotes_gpc()){
  function stripslashes_deep($value){
    $value = is_array($value)?array_map('stripslashes_deep', $value):(isset($value)?stripslashes($value):null);
    return $value;
  }
  $_POST = stripslashes_deep($_POST);
  $_GET = stripslashes_deep($_GET);
  $_COOKIE = stripslashes_deep($_COOKIE);
}

// 执行 config.php 中配置的url路由
foreach ($route_config as $key => $val){ 
	$key = str_replace(':any', '([^\/.]+)', str_replace(':num', '([0-9]+)', $key));
	if (preg_match('#^'.$key.'#', $url))$url = preg_replace('#^'.$key.'#', $val, $url);
}

//获取URL中每一段的参数';
$url = rtrim($url,'/');
$seg = explode('/',$url);
$des_dir = $dir = '';


/* 依次载入控制器上级所有目录的架构文件 __construct.php
*/
foreach($seg as $cur_dir) {
	$des_dir.=$cur_dir."/";
	if(is_file(APP.'c'.$des_dir.'__construct.php')) {
		require(APP.'c'.$des_dir.'__construct.php'); 
		$dir .=array_shift($seg).'/';
	}else { break; }
}


/* 根据 url 调用控制器中的方法，如果不存在返回 404 错误
* 默认请求 class main->index()
*/
$dir = $dir?$dir:'/';
array_unshift($seg,NULL);
$class  = isset($seg[1])?$seg[1]:'main';
$method = isset($seg[2])?$seg[2]:'index';
if(!is_file(APP.'c'.$dir.$class.'.php'))show_404();
require(APP.'c'.$dir.$class.'.php');
if(!class_exists($class))show_404();
if(!method_exists($class,$method))show_404();
$B2 = new $class();
call_user_func_array(array(&$B2, $method), array_slice($seg, 3));


/*
* load($path,$instantiate) 可以动态载入对象，如：控制器、Model、库类等
* $path 是类文件相对 app 的地址
* $instantiate 为 False 时，仅引用文件，不实例化对象
* $instantiate 为数组时，数组内容会作为参数传递给对象 
*/
function &load($path, $instantiate=TRUE){
  $param = FALSE;
  if(is_array($instantiate)) {
    $param = $instantiate;
    $instantiate = TRUE;
  }
  $file = explode('/',$path);
  $class_name = array_pop($file);
  $object_name = md5($path);
  
  static $objects = array();
  if (isset($objects[$object_name])) return $objects[$object_name];
  require(APP.$path.'.php');
  if ($instantiate == FALSE) $objects[$object_name] = TRUE;
  elseif ($param) $objects[$object_name] = new $class_name($param);
  else  $objects[$object_name] = new $class_name();
  return $objects[$object_name];
}


// 取得 url 的片段，如 url 是 /abc/def/g/  seg(1) = abc
function seg($i){
  global $seg;
  return isset($seg[$i])?$seg[$i]:false;
}


/* 调用 view 文件
* function view($view,$param = array(),$cache = FALSE)
* $view 是模板文件相对 app/v/ 目录的地址，地址应去除 .php 文件后缀
* $param 数组中的变量会传递给模板文件
* $cache = TRUE 时，不像浏览器输出结果，而是以 string 的形式 return
*/
function view($view,$param = array(),$cache = FALSE){
  if(!empty($param))extract($param);
  /*$token_key = substr(SITE_URL, 0, -1).$_SERVER['REQUEST_URI'];
  foreach ($_REQUEST as $k => $v){
	  if($k == 'token_name'){ continue; }
	  $token_key .= $k;
  }
  $token_key = md5($token_key);
  if (!isset($_SESSION[$token_key]) || !isset($_SESSION['token_name']) || !isset($_SESSION[$_SESSION['token_name']])){
	$val = md5(microtime());
	if (!isset($_SESSION['token_name']) || !isset($_REQUEST['token_name'])){
		$_SESSION['token_name'] = $token_key;
	}
	$_SESSION[$token_key] = $val;
  }
  $content = preg_replace('/<form(.*?)>(.*?)<\/form>/i', '<form$1><input type="hidden" value="'.$_SESSION[$_SESSION['token_name']].'" name="token_name"/>$2</form>', $content);*/
  ob_start();
  if(is_file(APP.$view.'.php')) {
    include APP.$view.'.php';
  } else {
    echo 'view '.$view.' desn\'t exsit';
    return false;
  }
  if ($cache === TRUE){
    $buffer = ob_get_contents();
    @ob_end_clean();
    return $buffer;
  }
}

// 写入日志
function write_log($level = 0 ,$content = 'none'){
	file_put_contents(APP.'log/'.$level.'-'.date('Y-m-d').'.log', $content , FILE_APPEND);
}

function show_404(){
	view('v/404');
	exit(1);
}

// 抽象的控制器类，建议所有的控制器均基层此类或者此类的子类 
class c {

	public $open_token = null; //令牌token验证
	public $val_array = '';
	
	public function set($name, $val){
		if (count($_POST) && $this->open_token && count($_REQUEST) && isset($_SESSION['token_name']) && isset($_SESSION[$_SESSION['token_name']]))
		{
			if (!isset($_REQUEST['token_name']))
				die('token not find');
			$val2 = trim($_REQUEST['token_name']);
			if ($val2 != $_SESSION[$_SESSION['token_name']])
			{
				unset($_SESSION[$_SESSION['token_name']]);
				unset($_SESSION['token_name']);
				die('token error');
			}
			unset($_SESSION[$_SESSION['token_name']]);
			unset($_SESSION['token_name']);
		}
		$this->$val_array[$name] = $val;
		unset($val);
	}
	
	function index(){
		echo 'test';
	}
	
}

//MYSQL PDO 连接方式
//sqlite $db = new pdoMysql('sqlite:my_database.sq3','user','password');
//mysql  $db = new pdoMysql('mysql:host=localhost;dbname=mydb','user','password');
class pdoMysql {

	public $db = null;
	public $last_query = null; //最后一个所执行的sql
	public $num_queries=0; //sql执行数量
	public $num_rows=0;
	public $func_call=null;
	
	public $timers = array();
	public $total_query_time = 0;
	public $do_profile = true;
	public $profile_times = array();
	
	public $is_cache = true; //是否开启文件缓存
	public $cache_queries = true; //是否开启非执行SQL类缓存
	public $cache_inserts = true; //是否开启执行SQL类缓存
	public $cache_timeout = 24; //小时
	public $cache_dir = 'cache_sql'; //缓存目录
	public $col_info = null; //缓存数据
	public $return_val = null;
	public $last_result = null;
	public $insert_id = null;

	function __construct($dsn='', $user='', $password='', $ssl=array()){
		try{
			if(!empty($ssl)){
				$this->db = new PDO($dsn, $user, $password, $ssl);
			}else{
				$this->db = new PDO($dsn, $user, $password);
			}
			$this->db->query('set names utf8;');
		} catch (PDOException $e) {
			die($e);
		}
	}
	
	//获取某行某列数据
	function get_var($query=null,$x=0,$y=0){
		$this->func_call = "\$db->get_one(\"$query\",$x,$y)";
		if($query){
			$this->query($query);
		}else{
			die('get_row query必须');
		}
		if($this->last_result[$y]){
			$values = array_values(get_object_vars($this->last_result[$y]));
		}
		return (isset($values[$x]) && $values[$x]!=='')?$values[$x]:null;
	}
	
	//获取x行key为name的数据
	function get_var_name($info_name="name",$col_offset=-1){
		if($this->col_info){
			if($col_offset == -1){
				$i=0;
				foreach($this->col_info as $col){
					$new_array[$i] = $col->{$info_type};
					$i++;
				}
				return $new_array;
			}else{
				return $this->col_info[$col_offset]->{$info_type};
			}
		}
	}
	
	//获取某行数据
	function get_row($query=null,$output=OBJECT,$y=0){
		$this->func_call = "\$db->get_row(\"$query\",$output,$y)";
		if($query){
			$this->query($query);
		}else{
			die('get_row query必须');
		}
		switch($output){
			case OBJECT:
				return $this->last_result[$y]?$this->last_result[$y]:null;
			break;
			case ARRAY_A:
				return $this->last_result[$y]?get_object_vars($this->last_result[$y]):null;
			break;
			case ARRAY_N:
				return $this->last_result[$y]?array_values(get_object_vars($this->last_result[$y])):null;
			break;
			default:
				die('get_row 第2个参数必须 OBJECT, ARRAY_A, ARRAY_N');
			break;
		}
	}
	
	//获取所有数据
	function get_all($query=null,$output=OBJECT){
		$this->func_call = "\$db->get_all(\"$query\",$output)";
		if($query){
			$this->query($query);
		}else{
			die('get_row query必须');
		}
		if($output == OBJECT){
			return $this->last_result;
		}elseif($output == ARRAY_A || $output == ARRAY_N){
			if($this->last_result){
				$i=0;
				foreach($this->last_result as $row){
					$new_array[$i] = get_object_vars($row);
					if($output == ARRAY_N){
						$new_array[$i] = array_values($new_array[$i]);
					}
					$i++;
				}
				return $new_array;
			}else{
				return array();
			}
		}
	}
	
	function select($table,$where='',$order='',$limit='',$fields=''){
		$select_sql = 'select ';
		$fields = !empty($fields)?$fields:'*';
		$select_sql.=$fields;
		$select_sql.= ' from `'.$table.'` ';
		!empty($where)?($select_sql.=' where '.$where):'';
		!empty($order)?($select_sql.=' order by '.$order):'';
        !empty($limit)?($select_sql.=' '.$limit):'';
		if($limit=='limit 1'){
			return $this->get_row($select_sql);
		}else{
			return $this->get_all($select_sql);
		}
	}
	
	function add($table,$data){
		$add_sql = 'insert into `'.$table.'` (';
		$value = $field = '';
		foreach($data as $k=>$v){
			$field .= '`'.$k.'`,';
			if(is_numeric($v))
				$value .= $this->escape($v).',';
			else
				$value .= '\''.$this->escape($v).'\',';
		}
		$add_sql .= rtrim($field,',').') values ('.rtrim($value,',').')';
		return $this->query($add_sql);
	}
	
	function delete($table,$where){
		return $this->query('delete from `'.$table.'` where '.$where);
	}
	
	function update($table,$data,$where){
		return $this->query('UPDATE `'.$table.'` SET '.$db->get_set($data).' WHERE '.$where);
	}
	
	function escape($str){
		switch (gettype($str)){
			case 'string' : $str = addslashes(stripslashes($str));
			break;
			case 'boolean' : $str = ($str === FALSE) ? 0 : 1;
			break;
			default : $str = ($str === NULL) ? 'NULL' : $str;
			break;
		}
		return $str;
	}
	
	function query($query){
		$query = str_replace("/[\n\r]/",'',trim($query));
		$this->flush();
		$this->func_call = "\$db->query(\"$query\")";
		$this->last_query = $query;
		$this->num_queries++;
		$this->timer_start($this->num_queries);
		if($cache = $this->get_cache($query)){
			$this->timer_update($this->num_queries);
			return $cache;
		}
		if(preg_match("/^(insert|delete|update|replace|drop|create)\s+/i",$query)){
			$this->return_val = $this->db->exec($query);
			if($this->catch_error()) return false;
			$is_insert = true;
			if (preg_match("/^(insert|replace)\s+/i",$query)){
				$this->insert_id = @$this->db->lastInsertId();	
			}
		}else{
			$squery = $this->db->query($query);
			if($this->catch_error()) return false;
			$is_insert = false;
			
			$col_count = $squery->columnCount();
			for($i=0;$i<$col_count;$i++){
				$this->col_info[$i] = new stdClass();
				if($meta = $squery->getColumnMeta($i)){					
					$this->col_info[$i]->name = $meta['name'];
					$this->col_info[$i]->type = !empty($meta['native_type'])?$meta['native_type']:'undefined';
					$this->col_info[$i]->max_length = '';
				}else{
					$this->col_info[$i]->name = 'undefined';
					$this->col_info[$i]->type = 'undefined';
					$this->col_info[$i]->max_length = '';
				}
			}
			
			$num_rows=0;
			while($row = @$squery->fetch(PDO::FETCH_ASSOC)){
				$this->last_result[$num_rows] = (object)$row;
				$num_rows++;
			}
			$this->num_rows = $num_rows;
			$this->return_val = $num_rows;
		}
		$this->store_cache($query,$is_insert);
	}
	
	//执行时间
	function timer_get_cur(){
		list($usec, $sec) = explode(" ",microtime());
		return ((float)$usec+(float)$sec);
	}
	function timer_start($timer_name){
		$this->timers[$timer_name] = $this->timer_get_cur();
	}
	function timer_elapsed($timer_name){
		return round($this->timer_get_cur()-$this->timers[$timer_name],2);
	}
	function timer_update($timer_name){
		if($this->do_profile){
		$this->profile_times[] = array(
			'query' => $this->last_query,
			'time' => $this->timer_elapsed($timer_name)
		); }
		$this->total_query_time += $this->timer_elapsed($timer_name);
	}
	
	//缓存SQL返回结果
	function store_cache($query,$is_insert){
		$cache_file = $this->cache_dir.'/'.md5($query);
		if($this->is_cache && ($this->cache_queries && !$is_insert) || ($this->cache_inserts && $is_insert)){
			if(!is_dir($this->cache_dir)){
				die('缓存目录[ '.$this->cache_dir.' ]不存在');
			}else{
				$result_cache = array(
					'col_info' => $this->col_info,
					'last_result' => $this->last_result,
					'num_rows' => $this->num_rows,
					'return_value' => $this->num_rows,
				);
				file_put_contents($cache_file, serialize($result_cache));
				if(file_exists($cache_file.'.updating'))
					unlink($cache_file.'.updating');
			}
		}
	}
	
	//获取sql缓存
	function get_cache($query){
		$cache_file = $this->cache_dir.'/'.md5($query);
		if($this->is_cache && file_exists($cache_file)){
			//缓存超时并且不存在.updating文件
			if( (time()-filemtime($cache_file))>($this->cache_timeout*3600) && !(file_exists($cache_file.'.updating')) ){
				touch($cache_file.'.updating');
			}else{
				$result_cache = unserialize(file_get_contents($cache_file));
				$this->col_info = $result_cache['col_info'];
				$this->last_result = $result_cache['last_result'];
				$this->num_rows = $result_cache['num_rows'];
				return $result_cache['return_value'];
			}
		}
	}
	
	
	/**********************************************************************
	*  使用:
	*  $db_data = array('test1'=>'1','test2'=>'2', 'created' => 'NOW()');
	*  $db->query("INSERT INTO users SET ".$db->get_set($db_data));
	*  ...OR...
	*  $db->query("UPDATE users SET ".$db->get_set($db_data)." WHERE user_id = 1");
	*
	* 输出:
	* test1 = '1', test2 = '2', created = NOW()
	*/
	function get_set($params){
		if(!is_array($params)){
			die('get_set 只能是数组');
			return;
		}
		$sql = array();
		foreach($params as $field => $val){
			if($val === 'true' || $val === true)
				$val = 1;
			if($val === 'false' || $val === false)
				$val = 0;
			switch($val){
				case 'NOW()' :
				case 'NULL' :
					$sql[] = "$field = $val";
				break;
				default :
					$sql[] = "$field = '".$this->escape($val)."'";
			}
		}
		return implode(', ',$sql);
	}
	
	function flush(){
		$this->last_result = null;
		$this->col_info = null;
		$this->last_query = null;
	}
	
	function catch_error(){
		$err_array = $this->db->errorInfo();
		if(isset($err_array[1]) && $err_array[1]!=25){
			$error_str = '';
			foreach($err_array as $entry){
				$error_str .= $entry.', ';
			}
			$error_str = substr($error_str,0,-2);
			die($error_str);
			return true;
		}
	}
	
	function log_dump(){
		ob_start();
		echo "<p><table><tr><td bgcolor=ffffff><blockquote><font color=000090>";
		echo "<pre><font face=arial>";
		echo "<font color=800080><b>simpleLZF</b> (v2.0) <b>Variable Log..</b></font>\n\n";
		echo "<font color=red>No Value / False</font>";
		echo "<b>Last Query</b> [$this->num_queries]<b>:</b> ".($this->last_query?$this->last_query:"NULL")."\n";
		echo "<b>Last Function Call:</b> ".($this->func_call?$this->func_call:"None")."\n";
		echo "<b>Last Rows Returned:</b> ".count($this->last_result)."\n";
		echo "</font></pre></font></blockquote></td></tr></table><font size=1 face=arial color=000000>lizhifeng</font>";
		echo "\n<hr size=1 noshade color=dddddd>";
		$html = ob_get_contents();
		ob_end_clean();
		return $html;
	}
	
}


//Memcache 操作类
class base_memcached{

	private $client_type;
	private $m;
	public  $host = '127.0.0.1';
	public  $port = '11211';
	public  $expiration = 0;
	public  $prefix = 'lzf';
	public  $compression = false;

	function __construct(){
		$this->client_type = class_exists('Memcache')?'Memcache':(class_exists('Memcached')?'Memcached':FALSE);
		if($this->client_type){
			switch($this->client_type){
				case 'Memcached':
	            $this->m = new Memcached();
	            break;
	            case 'Memcache':
	            $this->m = new Memcache();
	            break;
			}
			$this->auto_connect();
		}else{
			die('ERROR: Failed to load Memcached or Memcache Class');
		}
	}
	
	function auto_connect(){
		$configServer = array(
        	'host' => $this->host,
			'port' => $this->port,
			'weight' => 1,
        );
        if(!$this->add_server($configServer)){
            die('ERROR: Could not connect to the server named '.$this->host);
        }
	}
	
	function add_server($configServer){
		extract($configServer);
        return $this->m->addServer($host, $port, $weight);
	}
	
	/**
     * @param:$key key
     * @param:$value 值
     * @param:$expiration 过期时间
     * @return : TRUE or FALSE
    **/
	function add($key=NULL, $value=NULL, $expiration=0){
		$expiration = is_null($expiration)?$this->expiration:$expiration;
        if(is_array($key)){
            foreach($key as $multi){
                if(!isset($multi['expiration']) || $multi['expiration'] == ''){
                    $multi['expiration'] = $expiration;
                }
                $this->add($this->key_name($multi['key']), $multi['value'], $multi['expiration']);
            }
        }else{
            $this->local_cache[$this->key_name($key)] = $value;
            switch($this->client_type){
                case 'Memcache':
                    $add_status = $this->m->add($this->key_name($key), $value, $this->compression , $expiration);
                    break;
                default:
                case 'Memcached':
                    $add_status = $this->m->add($this->key_name($key), $value, $expiration);
                    break;
            }
            return $add_status;
        }

	}
	
	 /**
     * @Name   与add类似,但服务器有此键值时仍可写入替换
     * @param  $key key
     * @param  $value 值
     * @param  $expiration 过期时间
     * @return TRUE or FALSE
    **/
    
    function set($key = NULL, $value = NULL, $expiration = NULL){
        $expiration = is_null($expiration)?$this->expiration:$expiration;
        if(is_array($key)){
            foreach($key as $multi){
                if(!isset($multi['expiration']) || $multi['expiration'] == ''){
                    $multi['expiration'] = $expiration;
                }
                $this->set($this->key_name($multi['key']), $multi['value'], $multi['expiration']);
            }
        }else{
            $this->local_cache[$this->key_name($key)] = $value;
            switch($this->client_type){
                case 'Memcache':
                    $add_status = $this->m->set($this->key_name($key), $value, $this->compression, $expiration);
                    break;
                case 'Memcached':
                    $add_status = $this->m->set($this->key_name($key), $value, $expiration);
                    break;
            }
            return $add_status;
        }
    }
     
    /**
     * @Name   get 根据键名获取值
     * @param  $key key
     * @return array OR json object OR string...
    **/
    function get($key = NULL){
        if($this->m){
            if(isset($this->local_cache[$this->key_name($key)])){
                return $this->local_cache[$this->key_name($key)];
            }
            if(is_null($key)){
                return FALSE;
            }
            if(is_array($key)){
                foreach($key as $n=>$k){
                    $key[$n] = $this->key_name($k);
                }
                return $this->m->getMulti($key);
            }else{
                return $this->m->get($this->key_name($key));
            }
        }else{
            return FALSE;
        }
    }

    /**
     * @Name   delete
     * @param  $key key
     * @param  $expiration 服务端等待删除该元素的总时间
     * @return true OR false
    **/
    function delete($key, $expiration = NULL){
        if(is_null($key)){
            return FALSE;
        }
        $expiration = is_null($expiration)?$this->expiration:$expiration;
        if(is_array($key)){
            foreach($key as $multi){
                $this->delete($multi, $expiration);
            }
        }else{
            unset($this->local_cache[$this->key_name($key)]);
            return $this->m->delete($this->key_name($key), $expiration);
        }
    }

    /**
     * @Name   replace
     * @param  $key 要替换的key
     * @param  $value 要替换的value
     * @param  $expiration 到期时间
     * @return none
    **/
   function replace($key = NULL, $value = NULL, $expiration = NULL){
        $expiration = is_null($expiration)?$this->expiration:$expiration;
        if(is_array($key)){
            foreach($key as $multi) {
                if(!isset($multi['expiration']) || $multi['expiration'] == ''){
                    $multi['expiration'] = $this->config['config']['expiration'];
                }
                $this->replace($multi['key'], $multi['value'], $multi['expiration']);
            }
        }else{
            $this->local_cache[$this->key_name($key)] = $value;
            switch($this->client_type){
                case 'Memcache':
                    $replace_status = $this->m->replace($this->key_name($key), $value, MEMCACHE_COMPRESSION, $expiration);
                    break;
                case 'Memcached':
                    $replace_status = $this->m->replace($this->key_name($key), $value, $expiration);
                    break;
            }
            return $replace_status;
        }
    }

    /**
     * @Name   空所有缓存
     * @return none
    **/
    function flush(){
    	return $this->m->flush();
    }

    /**
     * @Name   获取服务器池中所有服务器的版本信息
    **/
    function getversion(){
        return $this->m->getVersion();
    }

    /**
     * @Name   获取服务器池的统计信息
    **/
    function getstats($type="items"){
        switch($this->client_type){
            case 'Memcache':
                $stats = $this->m->getStats($type);
                break;
            default:
            case 'Memcached':
                $stats = $this->m->getStats();
                break;
        }
        return $stats;
    }

    /**
     * @Name: 开启大值自动压缩
     * @param:$tresh 控制多大值进行自动压缩的阈值。
     * @param:$savings 指定经过压缩实际存储的值的压缩率，值必须在0和1之间。默认值0.2表示20%压缩率。
     * @return : true OR false
    **/
    function setcompressthreshold($tresh, $savings=0.2){
        switch($this->client_type){
            case 'Memcache':
                $setcompressthreshold_status = $this->m->setCompressThreshold($tresh, $savings=0.2);
                break;
            default:
                $setcompressthreshold_status = TRUE;
                break;
        }
        return $setcompressthreshold_status;
    }

    /**
     * @Name: 生成md5加密后的唯一键值
     * @param:$key key
     * @return : md5 string
    **/
    private function key_name($key){
        return md5(strtolower($this->prefix.$key));
    }

    /**
     * @Name: 向已存在元素后追加数据
     * @param:$key key
     * @param:$value value
     * @return : true OR false
    **/
    function append($key = NULL, $value = NULL){
//      if(is_array($key)){
//          foreach($key as $multi){
//              $this->append($multi['key'], $multi['value']);
//          }
//      }else{
            $this->local_cache[$this->key_name($key)] = $value;
            switch($this->client_type){
                case 'Memcache':
                    $append_status = $this->m->append($this->key_name($key), $value);
                    break;
                default:
                case 'Memcached':
                    $append_status = $this->m->append($this->key_name($key), $value);
                    break;
            }
            return $append_status;
//      }
    }
}