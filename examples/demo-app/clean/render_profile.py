"""Template rendering: user text is escaped before reaching markup."""

import html


def render_profile(display_name, bio):
    safe_name = html.escape(display_name, quote=True)
    safe_bio = html.escape(bio, quote=True)
    return f"<h1>{safe_name}</h1><div class='bio'>{safe_bio}</div>"
