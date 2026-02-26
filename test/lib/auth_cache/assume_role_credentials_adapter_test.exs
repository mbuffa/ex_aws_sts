defmodule ExAws.STS.AuthCache.AssumeRoleCredentialsAdapterTest do
  use ExUnit.Case, async: true
  alias ExAws.STS.AuthCache.AssumeRoleCredentialsAdapter

  import Mox

  test "#adapt_auth_config" do
    profile = "default"
    auth = test_loader(profile)

    body = """
    <AssumeRoleResponse>
      <AssumeRoleResult>
        <Credentials>
          <AccessKeyId>1</AccessKeyId>
          <SecretAccessKey>secret</SecretAccessKey>
          <SessionToken>token</SessionToken>
        </Credentials>
      </AssumeRoleResult>
      <ResponseMetadata><RequestId>req-id</RequestId></ResponseMetadata>
    </AssumeRoleResponse>
    """

    ExAws.Request.HttpMock
    |> expect(:request, fn _method,
                           _url,
                           "Action=AssumeRole&DurationSeconds=900&RoleArn=1111111%2Ftest_role&RoleSessionName=test&Version=2011-06-15",
                           _headers,
                           _opts ->
      {:ok, %{status_code: 200, body: body}}
    end)

    expected = %{
      access_key_id: "1",
      secret_access_key: "secret",
      security_token: "token",
      role_arn: auth.role_arn,
      role_session_name: auth.role_session_name,
      source_profile: auth.source_profile
    }

    assert expected ==
             AssumeRoleCredentialsAdapter.adapt_auth_config(auth, profile, 300, &test_loader/1)
  end

  test "#adapt_auth_config resolves {:system, env} role_arn" do
    System.put_env("ROLE_ARN", "1111111/test_role")
    on_exit(fn -> System.delete_env("ROLE_ARN") end)

    profile = "default"
    auth = test_loader("system-role")

    body = """
    <AssumeRoleResponse>
      <AssumeRoleResult>
        <Credentials>
          <AccessKeyId>1</AccessKeyId>
          <SecretAccessKey>secret</SecretAccessKey>
          <SessionToken>token</SessionToken>
        </Credentials>
      </AssumeRoleResult>
      <ResponseMetadata><RequestId>req-id</RequestId></ResponseMetadata>
    </AssumeRoleResponse>
    """

    ExAws.Request.HttpMock
    |> expect(:request, fn _method,
                           _url,
                           "Action=AssumeRole&DurationSeconds=900&RoleArn=1111111%2Ftest_role&RoleSessionName=test&Version=2011-06-15",
                           _headers,
                           _opts ->
      {:ok, %{status_code: 200, body: body}}
    end)

    expected = %{
      access_key_id: "1",
      secret_access_key: "secret",
      security_token: "token",
      role_arn: "1111111/test_role",
      role_session_name: auth.role_session_name,
      source_profile: auth.source_profile
    }

    assert expected ==
             AssumeRoleCredentialsAdapter.adapt_auth_config(auth, profile, 300, &test_loader/1)
  end

  test "#adapt_auth_config passes through auth when role_arn is missing" do
    profile = "default"
    auth = Map.delete(test_loader("default"), :role_arn)

    assert auth ==
             AssumeRoleCredentialsAdapter.adapt_auth_config(auth, profile, 300, &test_loader/1)
  end

  defp test_loader("default") do
    %{
      source_profile: "source",
      role_arn: "1111111/test_role",
      role_session_name: "test"
    }
  end

  defp test_loader("system-role") do
    %{
      source_profile: "source",
      role_arn: {:system, "ROLE_ARN"},
      role_session_name: "test"
    }
  end

  defp test_loader("source") do
    %{
      http_client: ExAws.Request.HttpMock,
      access_key_id: "1",
      secret_access_key: "secret",
      region: "us-east-1"
    }
  end
end
