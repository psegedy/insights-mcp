from typing import Any

import click

from insights_mcp_core.mcp import InsightsMCP
from insights_vulnerability_mcp.mcp import mcp as VulnerabilityMCP


MCPS: list[InsightsMCP] = [VulnerabilityMCP]


class InsightsMCPServer(InsightsMCP):
    def __init__(
        self,
        name: str | None = None,
        refresh_token: str | None = None,
        instructions: str | None = None,
        **settings: Any,
    ):
        name = name or "Red Hat Insights"
        super().__init__(
            name=name,
            refresh_token=refresh_token,
            instructions=instructions,
            **settings,
        )
        self.refresh_token = refresh_token
        self.init_insights_client(refresh_token)

    def register_mcps(self, allowed_mcps: list[str]):
        for mcp in MCPS:
            if mcp.name not in allowed_mcps:
                continue
            mcp.init_insights_client(self.refresh_token)
            self.mount(mcp)


@click.command()
@click.option(
    "--refresh-token",
    envvar="HCC_REFRESH_TOKEN",
    required=True,
    help="""
        Oauth2 refresh token to get an access token for console.redhat.com.
        You can get it from https://access.redhat.com/management/api.
        See https://access.redhat.com/articles/3626371
    """,
)
@click.option(
    "--toolset",
    envvar="HCC_TOOLSET",
    required=False,
    help="Red Hat Insights toolset to register. If not provided, all toolsets will be registered.",
    type=click.Choice([mcp.name for mcp in MCPS] + ["all"]),
    multiple=True,
    default=["all"],
)
def main(refresh_token: str, toolset: list[str]) -> None:
    mcp = InsightsMCPServer(refresh_token=refresh_token)
    if "all" in toolset:
        mcp.register_mcps([x.name for x in MCPS])
    else:
        mcp.register_mcps(toolset)
    mcp.run(transport="stdio")
