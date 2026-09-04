"""Main entrypoint: dispatches to argparse mode or interactive mode."""

from __future__ import annotations

import asyncio
import logging
import sys

from passforge.core.enums import LogEventType, PasswordCategory, PasswordStrength
from passforge.core.exceptions import PassforgeError
from passforge.core.logger import AccountabilityLogger, log_event
from passforge.cli.argument_parser import build_parser
from passforge.cli.interactive import run_interactive
from passforge.models.policy import PasswordPolicy
from passforge.services.exporter import ResultExporter
from passforge.services.generator import PasswordGeneratorService
from passforge.services.wordlist_service import WordlistService

_CATEGORY_MAP = {
    "alphanumeric": PasswordCategory.ALPHANUMERIC,
    "complex": PasswordCategory.COMPLEX,
    "passphrase": PasswordCategory.PASSPHRASE,
}
_STRENGTH_MAP = {
    "basic": PasswordStrength.BASIC,
    "strong": PasswordStrength.STRONG,
    "paranoid": PasswordStrength.PARANOID,
}


async def _run_scripted(args, logger: logging.Logger) -> int:
    policy = PasswordPolicy(exclude_chars=args.exclude_chars, exclude_similar=not args.no_exclude_similar)
    service = PasswordGeneratorService(
        policy=policy,
        wordlist_service=WordlistService(args.wordlist),
        logger=logger,
        max_concurrency=args.max_concurrency,
    )

    category = _CATEGORY_MAP[args.category]
    strength = _STRENGTH_MAP[args.strength]

    if args.count == 1:
        results = [await service.generate_one(args.length, category, strength)]
    else:
        results = await service.generate_many(args.count, args.length, category, strength)

    metadata = {
        "category": args.category,
        "strength": args.strength,
        "length": args.length,
        "count": args.count,
    }

    if args.output:
        exporter = ResultExporter(logger=logger)
        await exporter.export(results, args.output, metadata=metadata)
        print(f"Results saved to {args.output}")
    else:
        import json

        payload = {**metadata, "results": [r.to_dict() for r in results]}
        print(json.dumps(payload, indent=2))

    return 0


async def _amain() -> int:
    if len(sys.argv) == 1:
        acc_logger = AccountabilityLogger(console=True)
        logger = acc_logger.start()
        log_event(logger, logging.INFO, "Interactive session started", event_type=str(LogEventType.SESSION_START))
        try:
            return await run_interactive(logger)
        finally:
            log_event(logger, logging.INFO, "Interactive session ended", event_type=str(LogEventType.SESSION_END))
            acc_logger.stop()

    parser = build_parser()
    args = parser.parse_args()

    acc_logger = AccountabilityLogger(log_dir=args.log_dir, console=not args.quiet)
    logger = acc_logger.start()
    log_event(logger, logging.INFO, "Scripted session started", event_type=str(LogEventType.SESSION_START))
    try:
        return await _run_scripted(args, logger)
    except PassforgeError as exc:
        log_event(
            logger,
            logging.ERROR,
            exc.message,
            event_type=str(LogEventType.GENERATION_FAILURE),
            context=exc.to_dict(),
        )
        print(f"Error [{exc.error_code}]: {exc.message}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive catch-all
        log_event(logger, logging.CRITICAL, f"Unexpected error: {exc}", event_type=str(LogEventType.GENERATION_FAILURE))
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1
    finally:
        log_event(logger, logging.INFO, "Scripted session ended", event_type=str(LogEventType.SESSION_END))
        acc_logger.stop()


def main() -> None:
    try:
        exit_code = asyncio.run(_amain())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
