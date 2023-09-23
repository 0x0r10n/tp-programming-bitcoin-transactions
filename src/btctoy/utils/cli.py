from typing import (
    Any,
    List,
    Optional,
)

import typer

from btctoy.utils.logging import (
    LogLevel,
    init_logging,
)


def VersionOption(  # noqa: N802
    version: str,
) -> Any:  # noqa: ANN401 Any disallowed
    """
    Display version of the application and exit.
    """

    def _handle_option(value: bool) -> bool:
        if value:
            typer.echo(version)
            raise typer.Exit()
        return value

    return typer.Option(
        False,
        callback=_handle_option,
    )


def LogLevelOption(  # noqa: N802
    *,
    envvar_scope: Optional[str] = None,
    use_global: bool = True,
) -> Any:  # noqa: ANN401 Any disallowed
    """
    Set global log level for the application and init logging module.
    Note: use 'str' for this option type. I add unexpected issues by trying to use my LogLevel enum type...
    Probably related to https://github.com/tiangolo/typer/issues/223
    """
    log_levels = ", ".join(LogLevel.__members__.keys())

    def _handle_option(log_level: Optional[str]) -> str:
        log_level = log_level or LogLevel.INFO
        if log_level not in LogLevel.__members__.keys():
            raise typer.BadParameter(
                f"invalid choice {log_level} (choose from {log_levels})"
            )

        # note: I initially set the default value on the typer.Option definition below
        # but I observed a strange issue, probably a bug:
        # When the envvar is unset and we use sub applications for sub commands then the
        # log_level would be set to None instead of its default.
        # It results in Error: Invalid value for '--log-level': invalid choice:
        # Probably related to https://github.com/tiangolo/typer/issues/223
        init_logging(LogLevel(log_level), "btctoy")
        return log_level

    return typer.Option(
        None,  # don't put default here, see comment above
        envvar=get_envvar_names("LOG_LEVEL", envvar_scope, use_global),
        callback=_handle_option,
        help=f"Logging level to use (choose from {log_levels})",
    )


# Only use prefixed environment variables to avoid messing with other softwares config
ENVVAR_PREFIX = "BTCTOY"


def get_envvar_name(setting_name: str, envvar_scope: Optional[str] = None) -> str:
    """
    Return a normalized environment variable name base on a setting name and optional scope.
    Scopes are meant to use a value on different tools using a shared setting (e.g. log-level, ...)
    """
    result = f"{ENVVAR_PREFIX}_"
    if envvar_scope is not None:
        result = f'{result}{envvar_scope.replace(" ", "_").replace("-", "_").upper()}_'
    return f'{result}{setting_name.replace(" ", "_").replace("-", "_").upper()}'


def get_envvar_names(
    setting_name: str,
    envvar_scope: Optional[str] = None,
    use_global: bool = True,
) -> List[str]:
    """
    Returns the list of environment variables associated to a setting.
    """
    envvar = [get_envvar_name(setting_name)] if use_global else []
    if envvar_scope is not None:
        envvar = [get_envvar_name(setting_name, envvar_scope), *envvar]
    return envvar
