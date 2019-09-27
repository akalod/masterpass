<?php
/**
 * User    : Seyhan 'sTaRs' YILDIZ
 * Mail    : syhnyldz@gmail.com
 * Company : Digital Panzehir
 * Web     : www.digitalpanzehir.com
 * Date    : 14/1/19
 * Time    : 16:39
 */

namespace akalod;


use Carbon\Carbon;
use GuzzleHttp\Client;

/***
 * Class MasterPass
 * @package akalod
 *
 * Masterpass tarafı javascript SDK sını kullanmaya zorladığı için sadece token generat kısımını kullanmanızı öneririm.
 * kart saklama kart bilgisi alma kayıtlı kartla ödeme kısımları devre dışı bıraktım
 */
class MasterPass
{

    /**
     * bu kısımdaki verileri masterpass tan temin ediceksiniz
     */
    public static $macroMerchantId = "0***8197920111105035***";
    public static $encKey = "****2C40D1C0D802D73612E0C2B7****";
    public static $macKey = "****DB556AD174751898B6921E5A****";
    public static $clientId = "**7042**";

    public static $webUrl='https://blabla';
    public static $pamFile = 'masterpass.pem';

    private static $prod_endPoint = "https://ui.masterpassturkiye.com/v2/";
    private static $dev_endPoint = "https://test.masterpassturkiye.com/MasterpassJsonServerHandler/v2/";
    private static $prod_commit_endPoint = 'https://uatmmi.masterpassturkiye.com/MMIUIMasterPass_V2_LB/MerchantServices/MPGCommitPurchaseService.asmx?wsdl';
    private static $dev_commit_endPoint = 'https://test.masterpassturkiye.com/MMIUIMasterPass_V2/MerchantServices/MPGCommitPurchaseService.asmx?wsdl';
    private static $endPoint = "";
    private static $commit_endPoint = "";
    private static $callBackUrl = 'mpi';
    private static $target = 'test';

    private static $msisdn = "";//kullanıcıya ait kayıtlı telefon numarası
    private static $reqRefNumber = "1";
    private static $timeZone; // = GetTimezone();
    private static $datetime; // DateTime . Now . ToString("yyyyMMddHHmmss");
    private static $msisdnValidated = "01"; // 00 -> not validated , 01 -> validated..
    private static $userId = "";//kullanıcnın ID si
    private static $validationType = "01"; // 00 -> none, 01 -> otp , 02 -> mpin , 03 -> mpin&otp , 04 -> 3D Secure..
    private static $merchantType = "00"; // 00 -> macro_merchant_id ,  01 -> custom..
    private static $bankICA = "";
    private static $vposCurrencyCode = "TRY";
    private static $vposMerchantId = "";
    private static $VposMerchantTerminalId = "";
    private static $vposMerchantEmail = "";
    private static $vposTerminalUserId = "";
    private static $vposProvisionUserId = "";
    private static $vposProvisionPassword = "";
    private static $vposStoreKey = "";
    private static $vposPosnetId = "";
    private static $dataToEncrypt = "";
    private static $token = "";
    private static $client = "";

    const TAG_CLIENT_ID = "FF01";
    const TAG_TIMEZONE = "FF02";
    const TAG_DATETIME = "FF03";
    const TAG_MSISDN = "FF04";
    const TAG_REQ_REF_NUMBER = "FF05";
    const TAG_USER_ID = "FF06";
    const TAG_CLIENT_VALIDATED_MSISDN = "FF07";
    const TAG_VALIDATION_TYPE = "FF08";
    const TAG_MERCHANT_TYPE = "FF09";
    const TAG_VPOS_CURRENCY_CODE = "FF0A";
    const TAG_VPOS_MERCHANT_ID = "FF0B";
    const TAG_VPOS_MERCHANT_TERMINAL_ID = "FF0C";
    const TAG_VPOS_MERCHANT_EMAIL = "FF0D";
    const TAG_VPOS_TERMINAL_USER_ID = "FF0E";
    const TAG_VPOS_PROVISION_USER_ID = "FF0F";
    const TAG_VPOS_PROVISION_PASSWORD = "FF10";
    const TAG_VPOS_STORE_KEY = "FF11";
    const TAG_VPOS_POSNET_ID = "FF12";
    const TAG_BANK_ICA = "FF13";

    const PUBLIC_KEY_N = "03";
    const PUBLIC_KEY = "F619C53A37BAB059C583DA9AC4E2920FFC9D57E00885E82F7A0863DEAC43CE06374E45A1417DAC907C6CAC0AF1DDF1D7152192FED7A1D9255C97BC27E420E0742B95ED3C53C62995F42CB6EEDB7B1FBDD3E4F4A4AA935650DA81E763CA7074690032F6A6AF72802CC50394C2AFA5C9450A990E6F969A38571C8BC9E381125D2BEEC348AF919D7374FF10DC3E0B4367566CE929AD6EA323A475A677EB41C20B42D44E82E8A53DD52334D927394FCADF09";

    public static function calcCurrency($d = 0)
    {
        return number_format(floor($d * 100) / 100, 2, '.', '');
    }

    public static function pay($userId, $phone, $amount, $alias, $orderId)
    {
        /**
         * responseCode
         * 5010 ->  3dSecure bekleniyor
         * 5013 -> Kart Cvv bilgisi bekleniyor
         * 5002 -> kullanıcı kayıt SMS'i bekleniyor
         * 5001 -> kart doğrulama sms i bekleniyor
         * 0000 yada "" ise ödeme çekilmiştir.
         * 1056 -> Kullanıcı kartı veya kullanıcı bulunamıyor.
         */
        $amount = self::calcCurrency($amount) * 100;
        $d = self::dataSet($userId, $phone);
        $d['amount'] = (int)$amount;
        $d['referenceNo'] = "2001";
        $d['orderNo'] = $orderId;
        $d['listAccountName'] = $alias;
        $d['macroMerchantId'] = self::$macroMerchantId;
        return self::transaction($d, 'remotePurchaseOther', "/$orderId");

    }

    public static function setTarget($target)
    {
        self::$target = $target;
    }

    public static function getIP()
    {
        if (getenv("HTTP_CLIENT_IP")) {
            $ip = getenv("HTTP_CLIENT_IP");
        } elseif (getenv("HTTP_X_FORWARDED_FOR")) {
            $ip = getenv("HTTP_X_FORWARDED_FOR");
            if (strstr($ip, ',')) {
                $tmp = explode(',', $ip);
                $ip = trim($tmp[0]);
            }
        } else {
            $ip = getenv("REMOTE_ADDR");
        }
        return $ip;
    }

    public static function payCommit($orderId, $data, $amount)
    {
        if (self::$target == 'prod') {
            self::$commit_endPoint = self::$prod_commit_endPoint;
        } else {
            self::$commit_endPoint = self::$dev_commit_endPoint;
        }
        if ($data->mdStatus >= 5) {
            return false;
        }
        $data = [
            'transaction_header' => [
                'client_id' => self::$clientId,
                'request_datetime' => Carbon::now()->toIso8601ZuluString(),
                'request_reference_no' => $orderId,
                'send_sms_language' => 'tur',
                'send_sms' => 'Y',
                'ip_address' => self::getIP(),
                'client_type' => ''
            ],
            'transaction_body' => [
                'amount' => self::calcCurrency($amount) * 100,
                'macro_merchant_id' => self::$macroMerchantId,
                'order_no' => $orderId,
                'payment_type' => "SECURE_3D",
                'bank_ica' => '',
                'token' => $data->token
            ]
        ];

        $client = new \SoapClient(self::$commit_endPoint);
        try {
            $result = $client->CommitPurchase(['CommitPurchaseRequest' => $data]);
            return $result->CommitPurchaseResult;
        } catch (\Exception $e) {
            throw $e;
        }

    }

    private static function ascii2hex($ascii)
    {
        return implode(unpack("H*", $ascii));
    }

    private static function getTimeZone()
    {
        $timeZone = date('T');

        if ($timeZone > 0) {
            return sprintf("%02X", $timeZone);
        } elseif ($timeZone < 0) {
            return "8" . sprintf("%01X", (-1 * $timeZone));
        }

        return "00";
    }

    private static function rPattern($key, $param)
    {
        return $key . sprintf("%02X", strlen($param)) . self::ascii2hex($param);
    }

    private static function prepare()
    {
        if (self::$target == 'prod') {
            self::$endPoint = self::$prod_endPoint;
        } else {
            self::$endPoint = self::$dev_endPoint;
        }
        self::$client = new Client([
            'base_uri' => self::$endPoint,
            'timeout' => 20.0,
        ]);
    }

    public static function generateToken($userId, $gsm)
    {

        self::prepare();
        self::$userId = $userId;
        $gsm = self::phoneFilter($gsm);

        self::$msisdn = $gsm;
        self::$datetime = date('YmdHis');

        self::$dataToEncrypt = self::rPattern(self::TAG_CLIENT_ID, self::$clientId)
            . self::TAG_TIMEZONE . "01" . sprintf("%02X", self::getTimeZone())
            . self::rPattern(self::TAG_DATETIME, self::$datetime)
            . self::rPattern(self::TAG_MSISDN, self::$msisdn)
            . self::rPattern(self::TAG_REQ_REF_NUMBER, self::$reqRefNumber)
            . self::rPattern(self::TAG_USER_ID, self::$userId)
            . self::TAG_CLIENT_VALIDATED_MSISDN . "01" . self::$msisdnValidated . self::TAG_VALIDATION_TYPE . "01" . self::$validationType . self::TAG_MERCHANT_TYPE . "01" . self::$merchantType
            . self::rPattern(self::TAG_BANK_ICA, self::$bankICA)
            . self::rPattern(self::TAG_VPOS_CURRENCY_CODE, self::$vposCurrencyCode)
            . self::rPattern(self::TAG_VPOS_MERCHANT_ID, self::$vposMerchantId)
            . self::rPattern(self::TAG_VPOS_MERCHANT_TERMINAL_ID, self::$VposMerchantTerminalId)
            . self::rPattern(self::TAG_VPOS_MERCHANT_EMAIL, self::$vposMerchantEmail)
            . self::rPattern(self::TAG_VPOS_TERMINAL_USER_ID, self::$vposTerminalUserId)
            . self::rPattern(self::TAG_VPOS_PROVISION_USER_ID, self::$vposProvisionUserId)
            . self::rPattern(self::TAG_VPOS_PROVISION_PASSWORD, self::$vposProvisionPassword)
            . self::rPattern(self::TAG_VPOS_STORE_KEY, self::$vposStoreKey)
            . self::rPattern(self::TAG_VPOS_POSNET_ID, self::$vposPosnetId);

        if ((strlen(self::$dataToEncrypt) % 32) != 0) {
            self::$dataToEncrypt .= "8";
            while (true) {
                if ((strlen(self::$dataToEncrypt) % 32) == 0) {
                    break;
                } else {
                    self::$dataToEncrypt .= '0';
                }
            }
        }

        $inputText = pack("H*", self::$dataToEncrypt);
        $inputKey = pack("H*", self::$encKey);
        $iv = pack("H*", "00000000000000000000000000000000");
        $encryptedData = openssl_encrypt($inputText, "aes-128-cbc", $inputKey, OPENSSL_RAW_DATA, $iv);
        $encryptedData = strtoupper(substr(implode("", unpack("H*", $encryptedData)), 0, strlen(self::$dataToEncrypt)));

        $mac_key = strtoupper(hash_hmac('sha1', $encryptedData, self::$macKey));

        $token = $encryptedData . $mac_key;
        return $token;

    }

    public static function phoneFilter($gsm)
    {
        if (!isset($gsm)) {
            return "";
        }
        $gsm = str_replace(['+', '-', '(', ')', ' '], '', $gsm);
        if ($gsm[0] == '0') {
            $gsm = '9' . $gsm;
        } else if ($gsm[0] == '9') {
        } else {
            $gsm = '90' . $gsm;
        }
        return $gsm;
    }

    private static function getBack($r, $param = "")
    {
        $data = json_decode($r->getBody()->getContents())->Data->Body;

        if (!isset($data->Response->Result))
            return false;

        $detail = $data->Fault->Detail->ServiceFaultDetail;
        $rData = $data->Response->Result->TransactionBody;

        $rData->ResponseCode = $detail->ResponseCode;
        $rData->ResponseDesc = $detail->ResponseDesc;

        if (isset($detail->Url3D)) {
            $rData->Url3D = $detail->Url3D . '&returnUrl=' . self::$webUrl . self::$callBackUrl . $param;
        }
        if (isset($detail->Token))
            $rData->Token = $detail->Token;

        return $rData;
    }

    public static function setToken($token)
    {
        self::prepare();
        self::$token = $token;
    }

    public static function encrypt($string)
    {
        $rsa = new \phpseclib\Crypt\RSA();
        $publicKey = file_get_contents(self::$pamFile);
        $rsa->loadKey($publicKey);
        $rsa->setEncryptionMode(\phpseclib\Crypt\RSA::ENCRYPTION_PKCS1);
        return bin2hex($rsa->encrypt($string));

    }

    private static function transaction($data, $url, $param = '')
    {
        $request = self::$client->request('POST', $url, [
            'headers' => ['Content-Type' => 'application/json'],
            'body' => json_encode($data)
        ]);
        return self::getBack($request, $param);
    }

    public static function validateByUserId($id, $code, $token)
    {
        /*$r = Users::getUser($id);
        return self::validate($id, $code, $token, $r->phone);*/
    }

    public static function validate($userId, $code, $token, $phone = null)
    {
        self::prepare();
        $d = self::dataSet($userId, $phone);
        $d['userId'] = $userId;
        $d["validationCode"] = trim($code);
        $d["validationRefNo"] = trim($token);
        $d["referenceNo"] = "00000001";
        if (!$phone)
            $d["pinType"] = "otp";
        return self::transaction($d, 'validateTransaction');
    }

    public static function deleteCard($userId, $phone, $alias)
    {
        $d = self::dataSet($userId, $phone);
        $d['referenceNo'] = "1002";
        $d['accountAliasName'] = $alias;

        return self::transaction($d, 'deleteCard');
    }

    /**
     * Kart ekleme işlemi başarılı olma durumunda doğrulama kodu 5001 yada 5008 response code'u olarak döner
     * @param $userId
     * @param $phone
     * @param $aliasName
     * @param $expiryDate
     * @param $cardNo
     * @param $cvc
     * @return bool
     */
    public static function addCard($userId, $phone, $aliasName, $expiryDate, $cardNo, $cvc)
    {
        $d = self::dataSet($userId, $phone);
        $d["accountAliasName"] = $aliasName;
        $d["uiChannelType"] = "6";
        $d["referenceNo"] = "2000";
        $d["actionType"] = "A";
        $d["mobileAccountConfig"] = "MWA";
        $d["eActionType"] = "A";
        $d["cardTypeFlag"] = "05";
        $d["timeZone"] = "+03";
        $d["cpinFlag"] = "Y";
        $d["expiryDate"] = $expiryDate; //YYMM
        $d["rtaPan"] = self::encrypt($cardNo); //kart numarası
        $d["cvc"] = self::encrypt($cvc); //kart güvenlik numarası
        $d["defaultAccount"] = "Y";
        $d["delinkReason"] = "";
        $d["identityVerificationFlag"] = "N";

        return self::transaction($d, 'register');
    }

    private static function dataSet($userId, $phone = null)
    {

        $data = [
            "token" => self::$token,
            "clientId" => self::$clientId,
            "sendSmsLanguage" => "tur",
            "sendSms" => "N",
            "clientIp" => self::getIP(),
            "dateTime" => Carbon::now()->toIso8601ZuluString(),
            "version" => "34",
            "clientType" => "1"
        ];
        if ($phone)
            $data["msisdn"] = self::phoneFilter($phone);

        if (!self::$token) {
            self::$token = self::generateToken($userId, $phone);
            $data['token'] = self::$token;
        }

        return $data;
    }

    public static function cardList($userId, $phone)
    {
        $r = self::check($userId, $phone);
        if ($r) {
            $data = self::dataSet($userId, $phone);
            $data["listType"] = "ACCOUNT";
            $data["referenceNo"] = "00000000";

            $result = self::transaction($data, 'listManagement');
            $result->ListItems = $result->ListItems->ListItem;
        } else {
            $result = new \stdClass();
            $result->ListItems = [];
        }

        $result->NeedAssign = $r && $r->needAssign ? true : false;

        return $result;
    }


    /**
     * @param $id
     * @param $phone
     * @param $oldValue
     * @param $newValue
     * @param string $type
     * @return bool
     */
    public static function updateUser($id, $phone, $oldValue, $newValue, $type = 'USER_ID')
    {
        $d = self::dataSet($id, $phone);
        $d["referenceNo"] = "0003000";
        $d["theNewValue"] = $newValue;
        $d["oldValue"] = $oldValue;
        $d["valueType"] = $type;
        return self::transaction($d, 'updateUser');
    }

    public static function masterPassAssign($userId, $phone = null)
    {
        $d = self::dataSet($userId, $phone);
        $d["referenceNo"] = "00000011";
        $d["userId"] = $userId;
        return self::transaction($d, 'linkCardToClient');
    }

    public static function check($userId, $phone)
    {
        $data = self::dataSet($userId, $phone);
        $data["referenceNo"] = "1";
        $data["userId"] = $userId;

        $result = self::transaction($data, 'checkMasterPassEndUser');
        if ($result->AccountStatus == '' || $result->AccountStatus == "0000000000000000") {
            return false;
        }

        $result->needAssign = $result->AccountStatus[3] == "0" ? true : false;

        return $result;
    }

    /**
     * @param $id
     * @param $aliasName
     * @param $expiryDate
     * @param $cardNo
     * @param $cvc
     * @return bool
     */
    public static function addCardByUserId($id, $aliasName, $expiryDate, $cardNo, $cvc)
    {
        if (strlen($expiryDate) == 5) {
            $expiryDate_ex = $expiryDate[4];
            $expiryDate[4] = 0;
            $expiryDate[5] = $expiryDate_ex;
        }
        if (strlen($expiryDate) == 6) {
            $expiryDate = substr($expiryDate, 2);
        }

        /* bu kısım Users modelinden verileri alarak hızlı ekleme işlemine yaradığı için kaldırıldı, kendinize göre değiştiriniz
        $r = Users::getUser($id);
        return self::addCard($id, $r->phone, $aliasName, $expiryDate, $cardNo, $cvc);
        */
    }

    /**
     * @param $id
     * @param $aliasName
     * @return bool
     */
    public static function deleteCardByUserId($id, $aliasName)
    {
        /*$r = Users::getUser($id);
        return self::deleteCard($id, $r->phone, $aliasName);*/
    }

    /**
     * @param $id
     * @return bool
     */
    public static function cardListByUserId($id)
    {
      /*  $r = Users::getUser($id);
        return self::cardList($id, $r->phone);
    }

    public static function payByOrderId($orderId, $alias)
    {
        /* bu kısım entegre edildiği yazılıma özel olduğundan dolayı kaldırıldı
        $r = Orders::getOrderInfoWithUser($orderId);
        return self::pay($r->user_id, $r->phone, $r->payed_price, $alias, $orderId);
        */
    }

    public static function masterPassAssignByUserId($id)
    {
        /*
        $r = Users::getUser($id);
        return self::masterPassAssign($id, $r->phone);*/
    }

    public static function generateTokenByUserId($id)
    {
       /* $r = Users::getUser($id);
        return self::generateToken($id, $r->phone);*/
    }


}