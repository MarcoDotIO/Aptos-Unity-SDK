using System;
using System.Collections;
using System.Collections.Generic;
using Aptos.HdWallet;
using Aptos.Rest;
using NBitcoin;
using Unity.VisualScripting;
using UnityEngine;
using Aptos.Unity.Rest;
using Newtonsoft.Json;
using Aptos.Unity.Rest.Model;

public class AptosUILink : MonoBehaviour
{
    static public AptosUILink Instance { get; set; }

    [HideInInspector]
    public string mnemonicsKey = "MnemonicsKey";
    [HideInInspector]
    public string privateKey = "PrivateKey";
    [HideInInspector]
    public string currentAddressIndexKey = "CurrentAddressIndexKey";

    [SerializeField] private int accountNumLimit = 10;
    public List<string> addressList;

    public event Action<float> onGetBalance;

    private Wallet wallet;
    private string faucetEndpoint = "https://faucet.devnet.aptoslabs.com";

    private void Awake()
    {
        Instance = this;
    }

    void Start()
    {

    }

    void Update()
    {

    }

    public void InitWalletFromCache()
    {
        wallet = new Wallet(PlayerPrefs.GetString(mnemonicsKey));
        GetWalletAddress();
        LoadCurrentWalletBalance();
    }

    public bool CreateNewWallet()
    {
        Mnemonic mnemo = new Mnemonic(Wordlist.English, WordCount.Twelve);
        wallet = new Wallet(mnemo);

        PlayerPrefs.SetString(mnemonicsKey, mnemo.ToString());
        PlayerPrefs.SetInt(currentAddressIndexKey, 0);

        GetWalletAddress();
        LoadCurrentWalletBalance();

        if (mnemo.ToString() != string.Empty)
        {
            return true;
        }
        else
        {
            return false;
        }        
    }

    public bool RestoreWallet(string _mnemo)
    {
        try
        {
            wallet = new Wallet(_mnemo);
            PlayerPrefs.SetString(mnemonicsKey, _mnemo);
            PlayerPrefs.SetInt(currentAddressIndexKey, 0);

            GetWalletAddress();
            LoadCurrentWalletBalance();

            return true;
        }
        catch
        {

        }

        return false;
    }

    public List<string> GetWalletAddress()
    {
        addressList = new List<string>();

        for (int i = 0; i < accountNumLimit; i++)
        {
            var account = wallet.GetAccount(i);
            var addr = account.AccountAddress.ToString();

            addressList.Add(addr);
        }

        return addressList;
    }

    public string GetCurrentWalletAddress()
    {
        return addressList[PlayerPrefs.GetInt(currentAddressIndexKey)];
    }

    public void LoadCurrentWalletBalance()
    {
        StartCoroutine(RestClient.Instance.GetAccountBalance((returnResult) =>
        {
            if (returnResult == null)
            {
                //UIController.Instance.ToggleNotification(false, "Fail to Fetch the Balance");
                onGetBalance?.Invoke(0.0f);
            }
            else
            {
                AccountResourceCoin acctResourceCoin = JsonConvert.DeserializeObject<AccountResourceCoin>(returnResult);
                Debug.Log(acctResourceCoin.DataProp.Coin.Value);
                onGetBalance?.Invoke(float.Parse(acctResourceCoin.DataProp.Coin.Value));
            }

        }, wallet.GetAccount(PlayerPrefs.GetInt(currentAddressIndexKey)).AccountAddress));
    }

    public IEnumerator AirDrop(int _amount)
    {
        Coroutine cor = StartCoroutine(FaucetClient.Instance.FundAccount((returnResult) =>
        {
            Debug.Log("FAUCET RESPONSE: " + returnResult);
        }, wallet.GetAccount(PlayerPrefs.GetInt(currentAddressIndexKey)).AccountAddress.ToString()
            , _amount
            , faucetEndpoint));

        yield return cor;

        yield return new WaitForSeconds(1f);
        LoadCurrentWalletBalance();
        UIController.Instance.ToggleNotification(true, "Successfully Get Airdrop of " + AptoTokenToFloat((float)_amount) + " APT");
    }

    public IEnumerator SendToken(string targetAddress, int amount)
    {
        string transferResult = "";
        Coroutine cor = StartCoroutine(RestClient.Instance.Transfer((_transferResult) =>
        {
            transferResult = _transferResult;
        }, wallet.GetAccount(PlayerPrefs.GetInt(currentAddressIndexKey)), targetAddress, amount));

        yield return cor;

        yield return new WaitForSeconds(1f);
        LoadCurrentWalletBalance();
        UIController.Instance.ToggleNotification(true, "Successfully send " + AptoTokenToFloat((float)amount) + " APT to " + UIController.Instance.ShortenString(targetAddress, 4));
    }

    public float AptoTokenToFloat(float _token)
    {
        return _token / 100000000f;
    }

    public int AptoFloatToToken(float _amount)
    {
        return (int)(_amount * 100000000f);
    }
}
