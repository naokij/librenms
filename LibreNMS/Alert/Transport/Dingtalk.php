<?php
/* Copyright (C) 2020 Jiang Le <smartynaoki@gmail.com>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>. */

/**
 * Dingtalk API Transport
 * @author Jiang Le <smartynaoki@gmail.com>
 * @copyright 2020 Jiang Le, LibreNMS
 * @license GPL
 * @package LibreNMS
 * @subpackage Alerts
 */
namespace LibreNMS\Alert\Transport;

use LibreNMS\Alert\Transport;

class Dingtalk extends Transport
{
    const DINGTALK_API_ENDPOINT = "https://oapi.dingtalk.com/robot/send";

    public function deliverAlert($obj, $opts)
    {
        if (!empty($this->config)) {
            $opts['access-token'] = $this->config['dingtalk-token'];
            $opts['keyword'] = $this->config['dingtalk-keyword'];
            $opts['secret-key'] = $this->config['dingtalk-secret-key'];
        }
        return $this->contactDingtalk($obj, $opts);
    }

    public function contactDingtalk($obj, $opts)
    {   
        $sign_params = [];
        if ($opts["dingtalk-secret-key"]!="") {
            $ts = time();
            $hash = hash_hmac('sha256', sprintf("%d\n%s",$ts,$opts["dingtalk-secret-key"]),$opts["dingtalk-secret-key"]);
            $sign_params = [
                "timestamp" => $ts,
                "sign" => base64_encode($hash),
            ];
        }
        // Don't create tickets for resolutions
        if ($obj['state'] != 0) {
            $device = device_by_id_cache($obj['device_id']); // for event logging

            $access_token  = $opts['access-token'];
            $keyword = $opts['keyword'];
            $secret_key = $opts['secret-key'];
            $details     = "Librenms alert for: " . $obj['hostname'];
            if ($keyword != "") {
                $details = $keyword." > ".$details;
            }
            $description = $obj['msg'];
            
            $url         = sprintf("%s?access_token=%s",self::DINGTALK_API_ENDPOINT,url_encode($access_token));
            if ($sign_params != []){
                $url = sprintf("%s&timestamp=%d&sign=%s",$url,$sign_params["timestamp"], $sign_params["sign"]);
            }
            $curl        = curl_init();

            $postdata = [
                "msgtype" => "text",
                "text" => [
                    "content" => sprintf("%s\n%s", $details, $description),
                ],
            ];
            $datastring = json_encode($postdata);

            set_curl_proxy($curl);

            $headers = array('Accept: application/json', 'Content-Type: application/json');

            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($curl, CURLOPT_VERBOSE, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $datastring);

            $ret  = curl_exec($curl);
            $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            if ($code == 200) {
                $dingtalkout = json_decode($ret, true);
                d_echo("Created dingtalk issue " . $dingtalkout['key'] . " for " . $device);
                return true;
            } else {
                d_echo("dingtalk connection error: " . serialize($ret));
                return false;
            }
        }
    }

    public static function configTemplate()
    {
        return [
            'config' => [
                [
                    'title' => 'Access Token',
                    'name' => 'dingtalk-token',
                    'descr' => 'Dingtalk Access Token',
                    'type' => 'text',
                ],
                [
                    'title' => 'Security Keyword',
                    'name' => 'dingtalk-keyword',
                    'descr' => '自定义关键词。Dingtalk Security Keyword to include in alert message.',
                    'type'=> 'text',
                ],
                [
                    'title' => 'Sign Secret Key',
                    'name' => 'dingtalk-secret-key',
                    'descr' => '加签密钥。Secret key to sign the request.',
                    'type' => 'text',
                ]
            ],
            'validation' => [
                'dingtalk-token' => 'required|string',
                'dingtalk-keyword' => 'string',
                'dingtalk-secret-key' => 'string'
            ]
        ];
    }
}
